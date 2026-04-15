#!/usr/bin/env python3
"""
AgentWacht - Core Engine
=============================================
A production-grade, Zero Trust proxy for the Model Context Protocol.

Implements MCP 2025-11-25 Streamable HTTP transport with:
  - Multi-server aggregation (SSE + Stdio upstreams)
  - JSON-RPC 2.0 framing
  - MCP lifecycle (initialize -> initialized -> use -> shutdown)
  - RBAC, argument validation, DLP output sanitization
  - Structured JSONL audit logging
  - Per-user rate limiting

License: Apache-2.0
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Header, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

MCP_PROTOCOL_VERSION = "2025-11-25"
MCP_SUPPORTED_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
GATEWAY_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# Configuration Models
# ---------------------------------------------------------------------------

class UpstreamServer(BaseModel):
    name: str
    type: str  # 'sse' or 'stdio'
    url: Optional[str] = None
    command: Optional[str] = None
    args: Optional[list[str]] = None
    description: str = ""
    headers: Optional[dict[str, str]] = None
    timeout_seconds: int = 30
    restart_on_failure: bool = False
    health_check_path: Optional[str] = None


class User(BaseModel):
    username: str
    api_key: str
    roles: list[str]
    email: str
    department: str


class RolePermission(BaseModel):
    allow: Optional[str] = None
    deny: Optional[str] = None


class Role(BaseModel):
    description: str
    permissions: list[RolePermission]


class ArgumentGuard(BaseModel):
    tool_pattern: str
    argument_name: str
    validation_type: str
    regex: Optional[str] = None
    allowed_values: Optional[list[str]] = None
    custom_validator: Optional[str] = None
    max_size_bytes: Optional[int] = None
    case_sensitive: bool = True
    error_message: str


class OutputRedaction(BaseModel):
    pattern_type: str
    regex: str
    replacement: str
    applies_to_tools: list[str]
    except_roles: Optional[list[str]] = None


class GatewayConfig(BaseModel):
    upstream_servers: list[UpstreamServer]
    users: list[User]
    roles: dict[str, Role]
    policies: dict[str, Any]
    gateway_settings: dict[str, Any]


# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

config: Optional[GatewayConfig] = None
audit_logger: Optional[logging.Logger] = None
user_cache: dict[str, User] = {}

# Upstream state: name -> list of discovered tools
upstream_tools: dict[str, list[dict]] = {}
# Namespaced tool name -> (upstream_name, original_tool_name)
tool_registry: dict[str, tuple[str, str]] = {}
# Upstream health status
upstream_status: dict[str, str] = {}

# MCP sessions: session_id -> session state
mcp_sessions: dict[str, dict] = {}

# Rate limiting: username -> list of request timestamps
rate_limit_buckets: dict[str, list[float]] = defaultdict(list)

# Config file path (set during startup)
config_path_global: str = "policy.yaml"


# ---------------------------------------------------------------------------
# Config Loading
# ---------------------------------------------------------------------------

def load_config(config_path: str = "policy.yaml") -> GatewayConfig:
    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    # Environment variable substitution
    data_str = json.dumps(data)
    for match in re.finditer(r"\$\{([A-Z_]+)\}", data_str):
        env_var = match.group(1)
        env_val = os.environ.get(env_var, "")
        data_str = data_str.replace(match.group(0), env_val)
    data = json.loads(data_str)

    cfg = GatewayConfig(**data)

    # ── Community Edition limits ──
    # Max 2 roles (admin + one custom). Enterprise removes this limit.
    MAX_COMMUNITY_ROLES = 2
    if len(cfg.roles) > MAX_COMMUNITY_ROLES:
        allowed = dict(list(cfg.roles.items())[:MAX_COMMUNITY_ROLES])
        logging.warning(
            "Community edition: only %d roles allowed (loaded %d, keeping: %s). "
            "Upgrade to Enterprise for unlimited roles.",
            MAX_COMMUNITY_ROLES, len(cfg.roles), list(allowed.keys()),
        )
        cfg.roles = allowed

    # Community DLP: only credit_card pattern.
    COMMUNITY_DLP_PATTERNS = {"credit_card"}
    raw_rules = cfg.policies.get("output_redaction", [])
    if raw_rules:
        filtered = [r for r in raw_rules if r.get("pattern_type") in COMMUNITY_DLP_PATTERNS]
        if len(filtered) < len(raw_rules):
            logging.warning(
                "Community edition: DLP limited to %s patterns. "
                "Upgrade to Enterprise for full PII redaction (SSN, email, phone, API keys, cloud creds).",
                COMMUNITY_DLP_PATTERNS,
            )
        cfg.policies["output_redaction"] = filtered

    return cfg


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

def setup_audit_logger(log_path: str = "./agentwacht_audit.jsonl") -> logging.Logger:
    log_dir = Path(log_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("agentwacht_audit")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(log_path, mode="a")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def log_audit_event(
    user: str,
    method: str,
    tool: str = "",
    args: Optional[dict] = None,
    verdict: str = "SUCCESS",
    latency_ms: float = 0,
    redacted_count: int = 0,
    error: Optional[str] = None,
    session_id: str = "",
):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "user": user,
        "method": method,
        "tool": tool,
        "args_hash": hashlib.sha256(
            json.dumps(args or {}, sort_keys=True).encode()
        ).hexdigest()[:16],
        "policy_verdict": verdict,
        "upstream_latency_ms": round(latency_ms, 2),
        "redacted_pii_count": redacted_count,
        "error": error,
    }
    if audit_logger:
        audit_logger.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Pattern Matching
# ---------------------------------------------------------------------------

def match_glob(pattern: str, text: str) -> bool:
    regex = pattern.replace(".", "\\.").replace("*", ".*")
    return bool(re.match(f"^{regex}$", text))


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

def get_user(api_key: str) -> Optional[User]:
    if api_key in user_cache:
        return user_cache[api_key]
    for u in config.users:
        if u.api_key == api_key:
            user_cache[api_key] = u
            return u
    return None


def user_can_access(user: User, tool_name: str) -> bool:
    denies: list[str] = []
    allows: list[str] = []
    for role_name in user.roles:
        role = config.roles.get(role_name)
        if not role:
            continue
        for perm in role.permissions:
            if perm.deny:
                denies.append(perm.deny)
            if perm.allow:
                allows.append(perm.allow)
    for d in denies:
        if match_glob(d, tool_name):
            return False
    for a in allows:
        if match_glob(a, tool_name):
            return True
    return False


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

def check_rate_limit(username: str) -> bool:
    rl = config.gateway_settings.get("rate_limit", {})
    if not rl.get("enabled", False):
        return True
    rpm = rl.get("requests_per_minute", 60)
    now = time.time()
    window = 60.0
    bucket = rate_limit_buckets[username]
    rate_limit_buckets[username] = [t for t in bucket if now - t < window]
    if len(rate_limit_buckets[username]) >= rpm:
        return False
    rate_limit_buckets[username].append(now)
    return True


# ---------------------------------------------------------------------------
# Argument Validation
# ---------------------------------------------------------------------------

def validate_arguments(user: User, tool_name: str, arguments: dict) -> Optional[str]:
    guards = config.policies.get("argument_guards", [])
    for guard_data in guards:
        guard = ArgumentGuard(**guard_data)
        if not match_glob(guard.tool_pattern, tool_name):
            continue
        arg_value = arguments.get(guard.argument_name)
        if arg_value is None:
            continue
        if guard.validation_type == "regex_deny":
            flags = 0 if guard.case_sensitive else re.IGNORECASE
            if re.search(guard.regex, str(arg_value), flags):
                return guard.error_message
        elif guard.validation_type == "whitelist":
            if str(arg_value) not in (guard.allowed_values or []):
                return guard.error_message
    return None


# ---------------------------------------------------------------------------
# Output Sanitization (DLP)
# ---------------------------------------------------------------------------

def sanitize_output(user: User, tool_name: str, output: Any) -> tuple[Any, int]:
    if not isinstance(output, str):
        output = json.dumps(output)
        was_json = True
    else:
        was_json = False

    redaction_count = 0
    for rule_data in config.policies.get("output_redaction", []):
        rule = OutputRedaction(**rule_data)
        applies = any(match_glob(tp, tool_name) for tp in rule.applies_to_tools)
        if not applies:
            continue
        if rule.except_roles and set(user.roles) & set(rule.except_roles):
            continue
        matches = re.findall(rule.regex, output, re.IGNORECASE)
        if matches:
            output = re.sub(rule.regex, rule.replacement, output, flags=re.IGNORECASE)
            redaction_count += len(matches)

    if was_json:
        try:
            output = json.loads(output)
        except Exception:
            pass
    return output, redaction_count


# ---------------------------------------------------------------------------
# Upstream Discovery
# ---------------------------------------------------------------------------

async def discover_upstream(server: UpstreamServer) -> list[dict]:
    """Probe an upstream MCP server for its tool list."""
    if server.type != "sse" or not server.url:
        upstream_status[server.name] = "skipped"
        return []

    headers = dict(server.headers or {})

    try:
        async with httpx.AsyncClient(timeout=server.timeout_seconds) as client:
            # Health check
            if server.health_check_path:
                base = server.url.rsplit("/", 1)[0] if "/" in server.url[8:] else server.url
                health_url = base.rstrip("/") + server.health_check_path
                resp = await client.get(health_url, headers=headers)
                if resp.status_code >= 400:
                    upstream_status[server.name] = "unhealthy"
                    logging.warning("Upstream %s unhealthy: HTTP %d", server.name, resp.status_code)
                    return []

            # MCP tools/list via JSON-RPC POST
            jsonrpc_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
            resp = await client.post(
                server.url,
                json=jsonrpc_req,
                headers={
                    **headers,
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                tools = data.get("result", {}).get("tools", [])
                upstream_status[server.name] = "connected"
                logging.info("Discovered %d tools from %s", len(tools), server.name)
                return tools

            upstream_status[server.name] = "connected"
            return []

    except Exception as exc:
        upstream_status[server.name] = "disconnected"
        logging.error("Failed to discover %s: %s", server.name, exc)
        return []


async def discover_all_upstreams():
    """Discover tools from all configured upstream servers."""
    global upstream_tools, tool_registry
    upstream_tools.clear()
    tool_registry.clear()

    sep = config.gateway_settings.get("namespace_separator", "_")
    tasks = [discover_upstream(s) for s in config.upstream_servers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for server, result in zip(config.upstream_servers, results):
        if isinstance(result, Exception):
            logging.error("Discovery error for %s: %s", server.name, result)
            continue
        tools = result if isinstance(result, list) else []
        upstream_tools[server.name] = tools
        for tool in tools:
            name = tool.get("name", "unknown")
            ns_name = f"{server.name}{sep}{name}"
            tool_registry[ns_name] = (server.name, name)
            tool["_namespaced"] = ns_name

    total = sum(len(t) for t in upstream_tools.values())
    logging.info("Total tools: %d across %d upstreams", total, len(config.upstream_servers))


# ---------------------------------------------------------------------------
# Upstream Tool Execution
# ---------------------------------------------------------------------------

async def execute_upstream_tool(
    upstream_name: str, original_tool_name: str, arguments: dict
) -> dict:
    server = next((s for s in config.upstream_servers if s.name == upstream_name), None)
    if not server or server.type != "sse" or not server.url:
        return {"error": f"Upstream {upstream_name} not available"}

    headers = dict(server.headers or {})
    jsonrpc_req = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {"name": original_tool_name, "arguments": arguments},
    }

    try:
        async with httpx.AsyncClient(timeout=server.timeout_seconds) as client:
            resp = await client.post(
                server.url,
                json=jsonrpc_req,
                headers={
                    **headers,
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    return data["result"]
                if "error" in data:
                    return {"error": data["error"]}
            return {"error": f"Upstream returned HTTP {resp.status_code}"}
    except Exception as exc:
        return {"error": f"Upstream call failed: {exc}"}


# ---------------------------------------------------------------------------
# JSON-RPC Helpers
# ---------------------------------------------------------------------------

def jsonrpc_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def jsonrpc_error(id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": err}


PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# ---------------------------------------------------------------------------
# MCP Protocol Handlers
# ---------------------------------------------------------------------------

def handle_initialize(req_id: Any, params: dict, session_id: str) -> dict:
    client_info = params.get("clientInfo", {})
    logging.info(
        "MCP initialize from %s v%s",
        client_info.get("name", "unknown"),
        client_info.get("version", "?"),
    )
    client_version = params.get("protocolVersion", MCP_PROTOCOL_VERSION)
    negotiated_version = client_version if client_version in MCP_SUPPORTED_VERSIONS else MCP_PROTOCOL_VERSION
    mcp_sessions[session_id] = {
        "initialized": False,
        "client_info": client_info,
        "protocol_version": negotiated_version,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return jsonrpc_response(req_id, {
        "protocolVersion": negotiated_version,
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {"subscribe": False, "listChanged": False},
            "prompts": {"listChanged": False},
        },
        "serverInfo": {
            "name": "AgentWacht",
            "version": GATEWAY_VERSION,
        },
    })


def handle_initialized(session_id: str):
    if session_id in mcp_sessions:
        mcp_sessions[session_id]["initialized"] = True
        logging.info("Session %s initialized", session_id[:8])


async def handle_tools_list(req_id: Any, params: dict, user: User) -> dict:
    all_tools = []
    sep = config.gateway_settings.get("namespace_separator", "_")

    for server_name, tools in upstream_tools.items():
        for tool in tools:
            ns_name = tool.get("_namespaced", f"{server_name}{sep}{tool.get('name', '')}")
            if user_can_access(user, ns_name):
                all_tools.append({
                    "name": ns_name,
                    "description": tool.get("description", ""),
                    "inputSchema": tool.get("inputSchema", {"type": "object", "properties": {}}),
                })

    all_tools.extend(_builtin_tools(user))
    logging.info("User %s sees %d tools", user.username, len(all_tools))
    return jsonrpc_response(req_id, {"tools": all_tools})


def _builtin_tools(user: User) -> list[dict]:
    tools = [
        {
            "name": "gateway_health",
            "description": "Health status of the MCP Gateway and upstream servers.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "gateway_audit_summary",
            "description": "Summary of recent audit events.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Number of entries", "default": 10},
                },
            },
        },
    ]
    return tools


async def handle_tools_call(
    req_id: Any, params: dict, user: User, session_id: str
) -> dict:
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    start = time.time()

    # Built-in tools
    if tool_name == "gateway_health":
        result = _tool_gateway_health()
        latency = (time.time() - start) * 1000
        log_audit_event(user.username, "tools/call", tool_name, arguments, "SUCCESS", latency, session_id=session_id)
        return jsonrpc_response(req_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

    if tool_name == "gateway_audit_summary":
        result = _tool_audit_summary(arguments.get("limit", 10))
        latency = (time.time() - start) * 1000
        log_audit_event(user.username, "tools/call", tool_name, arguments, "SUCCESS", latency, session_id=session_id)
        return jsonrpc_response(req_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})

    # RBAC
    if not user_can_access(user, tool_name):
        latency = (time.time() - start) * 1000
        log_audit_event(user.username, "tools/call", tool_name, arguments, "PERMISSION_DENIED", latency, session_id=session_id)
        return jsonrpc_error(req_id, -32001, f"Access denied: {user.username} cannot use {tool_name}")

    # Argument validation
    violation = validate_arguments(user, tool_name, arguments)
    if violation:
        latency = (time.time() - start) * 1000
        log_audit_event(user.username, "tools/call", tool_name, arguments, "ARGUMENT_VIOLATION", latency, error=violation, session_id=session_id)
        return jsonrpc_error(req_id, -32001, f"Policy violation: {violation}")

    # Route to upstream
    routing = tool_registry.get(tool_name)
    if not routing:
        return jsonrpc_error(req_id, METHOD_NOT_FOUND, f"Tool {tool_name} not found")

    upstream_name, original_name = routing
    result = await execute_upstream_tool(upstream_name, original_name, arguments)

    if "error" in result:
        latency = (time.time() - start) * 1000
        log_audit_event(user.username, "tools/call", tool_name, arguments, "EXECUTION_FAILED", latency, error=str(result["error"]), session_id=session_id)
        return jsonrpc_error(req_id, INTERNAL_ERROR, str(result["error"]))

    # DLP
    content = result.get("content", [])
    redaction_count = 0
    for item in content:
        if item.get("type") == "text" and "text" in item:
            item["text"], count = sanitize_output(user, tool_name, item["text"])
            redaction_count += count

    latency = (time.time() - start) * 1000
    log_audit_event(user.username, "tools/call", tool_name, arguments, "SUCCESS", latency, redaction_count, session_id=session_id)
    return jsonrpc_response(req_id, {"content": content})


def handle_resources_list(req_id: Any) -> dict:
    return jsonrpc_response(req_id, {"resources": []})


def handle_prompts_list(req_id: Any) -> dict:
    return jsonrpc_response(req_id, {"prompts": []})


# ---------------------------------------------------------------------------
# Built-in Tool Implementations
# ---------------------------------------------------------------------------

def _tool_gateway_health() -> dict:
    return {
        "status": "healthy",
        "version": GATEWAY_VERSION,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "upstreams": {
            name: {
                "status": upstream_status.get(name, "unknown"),
                "tools": len(upstream_tools.get(name, [])),
            }
            for name in (s.name for s in config.upstream_servers)
        },
        "active_sessions": len(mcp_sessions),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _tool_audit_summary(limit: int = 10) -> dict:
    audit_path = config.gateway_settings.get("audit_log", {}).get(
        "file_path", "./agentwacht_audit.jsonl"
    )
    try:
        lines = Path(audit_path).read_text().strip().split("\n")
        entries = [json.loads(line) for line in lines[-limit:]]
        return {"total_entries": len(lines), "recent": entries}
    except Exception:
        return {"total_entries": 0, "recent": []}


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global config, audit_logger, config_path_global

    config_path_global = os.environ.get("GATEWAY_CONFIG", "policy.yaml")
    config = load_config(config_path_global)
    logging.info("Loaded config: %d upstreams, %d users", len(config.upstream_servers), len(config.users))

    audit_path = config.gateway_settings.get("audit_log", {}).get(
        "file_path", "./agentwacht_audit.jsonl"
    )
    audit_logger = setup_audit_logger(audit_path)

    await discover_all_upstreams()
    logging.info("AgentWacht v%s started", GATEWAY_VERSION)

    yield

    mcp_sessions.clear()
    logging.info("Gateway shutdown complete")


app = FastAPI(
    title="AgentWacht",
    description="Zero Trust proxy for Model Context Protocol",
    version=GATEWAY_VERSION,
    lifespan=lifespan,
)


def _extract_api_key(request: Request, header_val: Optional[str]) -> Optional[str]:
    if header_val:
        return header_val
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.query_params.get("api_key")


def _get_session_id(request: Request) -> str:
    return request.headers.get("MCP-Session-Id", "")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    return _tool_gateway_health()


@app.post("/mcp")
async def mcp_endpoint(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """MCP Streamable HTTP endpoint. Accepts JSON-RPC 2.0 over POST."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(jsonrpc_error(None, PARSE_ERROR, "Invalid JSON"), status_code=400)

    jsonrpc = body.get("jsonrpc")
    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params", {})

    if jsonrpc != "2.0":
        return JSONResponse(jsonrpc_error(req_id, INVALID_REQUEST, "Expected jsonrpc 2.0"), status_code=400)

    session_id = _get_session_id(request)

    # initialize (no auth required)
    if method == "initialize":
        if not session_id:
            session_id = secrets.token_urlsafe(32)
        result = handle_initialize(req_id, params, session_id)
        negotiated = mcp_sessions[session_id]["protocol_version"]
        resp = JSONResponse(result)
        resp.headers["MCP-Session-Id"] = session_id
        resp.headers["MCP-Protocol-Version"] = negotiated
        return resp

    # notifications/initialized
    if method == "notifications/initialized":
        handle_initialized(session_id)
        return Response(status_code=202)

    # All other methods require auth
    api_key = _extract_api_key(request, x_api_key)
    if not api_key:
        return JSONResponse(
            jsonrpc_error(req_id, -32000, "Authentication required: provide X-API-Key header"),
            status_code=401,
        )

    user = get_user(api_key)
    if not user:
        log_audit_event("unknown", method, verdict="AUTH_FAILED", session_id=session_id)
        return JSONResponse(jsonrpc_error(req_id, -32000, "Invalid API key"), status_code=401)

    # Rate limit
    if not check_rate_limit(user.username):
        log_audit_event(user.username, method, verdict="RATE_LIMITED", session_id=session_id)
        return JSONResponse(jsonrpc_error(req_id, -32000, "Rate limit exceeded"), status_code=429)

    # Validate session
    if session_id and session_id not in mcp_sessions:
        return JSONResponse(jsonrpc_error(req_id, -32000, "Invalid or expired session"), status_code=404)

    # Validate protocol version header
    proto_version = request.headers.get("MCP-Protocol-Version", "")
    if proto_version and proto_version not in MCP_SUPPORTED_VERSIONS:
        return JSONResponse(
            jsonrpc_error(req_id, INVALID_REQUEST, f"Unsupported protocol version: {proto_version}"),
            status_code=400,
        )

    # Route by method
    if method == "tools/list":
        result = await handle_tools_list(req_id, params, user)
        log_audit_event(user.username, method, verdict="SUCCESS", session_id=session_id)
        return JSONResponse(result)

    if method == "tools/call":
        result = await handle_tools_call(req_id, params, user, session_id)
        return JSONResponse(result)

    if method == "resources/list":
        return JSONResponse(handle_resources_list(req_id))

    if method == "prompts/list":
        return JSONResponse(handle_prompts_list(req_id))

    if method == "ping":
        return JSONResponse(jsonrpc_response(req_id, {}))

    # Unknown notifications return 202
    if req_id is None:
        return Response(status_code=202)

    return JSONResponse(jsonrpc_error(req_id, METHOD_NOT_FOUND, f"Unknown method: {method}"))


@app.delete("/mcp")
async def mcp_session_terminate(request: Request):
    """Terminate an MCP session (spec Section 2.5)."""
    session_id = _get_session_id(request)
    if session_id and session_id in mcp_sessions:
        del mcp_sessions[session_id]
        logging.info("Session %s terminated", session_id[:8])
        return Response(status_code=200)
    return Response(status_code=404)


@app.get("/mcp")
async def mcp_sse_listen(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """SSE stream for server-initiated messages, or server info if unauthenticated."""
    api_key = _extract_api_key(request, x_api_key)
    if not api_key:
        return await root()
    user = get_user(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    async def event_stream():
        event_id = str(uuid.uuid4())
        yield f"id: {event_id}\ndata: \n\n"
        try:
            while True:
                await asyncio.sleep(30)
                yield f"id: {uuid.uuid4()}\ndata: {json.dumps({'type': 'ping'})}\n\n"
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


# Legacy REST endpoints

@app.post("/tools/list")
async def legacy_tools_list(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    api_key = _extract_api_key(request, x_api_key)
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    user = get_user(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    result = await handle_tools_list(1, {}, user)
    return result.get("result") if isinstance(result, dict) else result


@app.post("/tools/call")
async def legacy_tools_call(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    api_key = _extract_api_key(request, x_api_key)
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    user = get_user(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    body = await request.json()
    result = await handle_tools_call(1, body, user, "")
    return result


@app.get("/")
async def root():
    return {
        "service": "AgentWacht",
        "version": GATEWAY_VERSION,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "endpoints": {
            "mcp": "POST /mcp (Streamable HTTP)",
            "mcp_sse": "GET /mcp (SSE listen)",
            "health": "GET /health",
            "legacy_list": "POST /tools/list",
            "legacy_call": "POST /tools/call",
        },
        "edition": "community",
        "security": "Zero Trust RBAC + DLP + Argument Validation",
        "upstream_servers": len(config.upstream_servers) if config else 0,
        "total_tools": len(tool_registry),
    }

