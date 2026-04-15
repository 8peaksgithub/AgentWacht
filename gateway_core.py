#!/usr/bin/env python3
"""
MCP Shield - Core Engine
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
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
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

    return GatewayConfig(**data)


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

def setup_audit_logger(log_path: str = "./mcp_shield_audit.jsonl") -> logging.Logger:
    log_dir = Path(log_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("mcp_shield_audit")
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
            "name": "MCP Shield",
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
    if "admin" in user.roles:
        tools.append({
            "name": "gateway_refresh_upstreams",
            "description": "Re-discover all upstream MCP server tools.",
            "inputSchema": {"type": "object", "properties": {}},
        })
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

    if tool_name == "gateway_refresh_upstreams":
        if "admin" not in user.roles:
            return jsonrpc_error(req_id, -32001, "Admin role required")
        await discover_all_upstreams()
        latency = (time.time() - start) * 1000
        log_audit_event(user.username, "tools/call", tool_name, arguments, "SUCCESS", latency, session_id=session_id)
        return jsonrpc_response(req_id, {"content": [{"type": "text", "text": "Upstream discovery complete"}]})

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
        "file_path", "./mcp_shield_audit.jsonl"
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
        "file_path", "./mcp_shield_audit.jsonl"
    )
    audit_logger = setup_audit_logger(audit_path)

    await discover_all_upstreams()
    logging.info("MCP Shield v%s started", GATEWAY_VERSION)

    yield

    mcp_sessions.clear()
    logging.info("Gateway shutdown complete")


app = FastAPI(
    title="MCP Shield",
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
        "service": "MCP Shield",
        "version": GATEWAY_VERSION,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "endpoints": {
            "mcp": "POST /mcp (Streamable HTTP)",
            "mcp_sse": "GET /mcp (SSE listen)",
            "health": "GET /health",
            "admin": "GET /admin (Dashboard)",
            "legacy_list": "POST /tools/list",
            "legacy_call": "POST /tools/call",
        },
        "security": "Zero Trust RBAC + DLP + Argument Validation",
        "upstream_servers": len(config.upstream_servers) if config else 0,
        "total_tools": len(tool_registry),
    }


# ---------------------------------------------------------------------------
# Admin helpers
# ---------------------------------------------------------------------------

def _require_admin(api_key: Optional[str], request: Request) -> User:
    key = _extract_api_key(request, api_key)
    if not key:
        raise HTTPException(status_code=401, detail="Admin API key required")
    user = get_user(key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if "admin" not in user.roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def _save_config():
    raw = config.model_dump()
    with open(config_path_global, "w") as f:
        yaml.dump(raw, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


async def _reload_config():
    global config, user_cache
    config = load_config(config_path_global)
    user_cache.clear()
    await discover_all_upstreams()
    logging.info("Config reloaded: %d upstreams, %d users", len(config.upstream_servers), len(config.users))


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------

@app.get("/admin/api/overview")
async def admin_overview(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    return {
        "version": GATEWAY_VERSION,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "upstreams": [
            {
                "name": s.name,
                "type": s.type,
                "url": s.url or "(stdio)",
                "description": s.description,
                "status": upstream_status.get(s.name, "unknown"),
                "tools": len(upstream_tools.get(s.name, [])),
                "timeout_seconds": s.timeout_seconds,
            }
            for s in config.upstream_servers
        ],
        "users": [
            {
                "username": u.username,
                "roles": u.roles,
                "email": u.email,
                "department": u.department,
                "api_key_preview": u.api_key[:8] + "..." if len(u.api_key) > 8 else "***",
            }
            for u in config.users
        ],
        "roles": {
            name: {"description": role.description, "permissions": [p.model_dump() for p in role.permissions]}
            for name, role in config.roles.items()
        },
        "sessions": len(mcp_sessions),
        "total_tools": len(tool_registry),
        "rate_limit": config.gateway_settings.get("rate_limit", {}),
        "policies": {
            "argument_guards": len(config.policies.get("argument_guards", [])),
            "output_redaction": len(config.policies.get("output_redaction", [])),
        },
    }


@app.get("/admin/api/upstreams")
async def admin_list_upstreams(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    return [
        {
            **s.model_dump(),
            "status": upstream_status.get(s.name, "unknown"),
            "discovered_tools": [
                {"name": t.get("name"), "description": t.get("description", "")}
                for t in upstream_tools.get(s.name, [])
            ],
        }
        for s in config.upstream_servers
    ]


@app.post("/admin/api/upstreams")
async def admin_add_upstream(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    body = await request.json()
    new_server = UpstreamServer(**body)
    if any(s.name == new_server.name for s in config.upstream_servers):
        raise HTTPException(status_code=409, detail=f"Upstream '{new_server.name}' already exists")
    config.upstream_servers.append(new_server)
    _save_config()
    await discover_upstream(new_server)
    return {"status": "created", "name": new_server.name}


@app.put("/admin/api/upstreams/{name}")
async def admin_update_upstream(
    name: str,
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    body = await request.json()
    for i, s in enumerate(config.upstream_servers):
        if s.name == name:
            updated = UpstreamServer(**{**s.model_dump(), **body, "name": name})
            config.upstream_servers[i] = updated
            _save_config()
            await discover_upstream(updated)
            return {"status": "updated", "name": name}
    raise HTTPException(status_code=404, detail=f"Upstream '{name}' not found")


@app.delete("/admin/api/upstreams/{name}")
async def admin_delete_upstream(
    name: str,
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    original_len = len(config.upstream_servers)
    config.upstream_servers = [s for s in config.upstream_servers if s.name != name]
    if len(config.upstream_servers) == original_len:
        raise HTTPException(status_code=404, detail=f"Upstream '{name}' not found")
    upstream_tools.pop(name, None)
    upstream_status.pop(name, None)
    tool_registry_clean = {k: v for k, v in tool_registry.items() if v[0] != name}
    tool_registry.clear()
    tool_registry.update(tool_registry_clean)
    _save_config()
    return {"status": "deleted", "name": name}


@app.get("/admin/api/users")
async def admin_list_users(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    return [
        {
            "username": u.username,
            "roles": u.roles,
            "email": u.email,
            "department": u.department,
            "api_key_preview": u.api_key[:8] + "..." if len(u.api_key) > 8 else "***",
        }
        for u in config.users
    ]


@app.post("/admin/api/users")
async def admin_add_user(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    body = await request.json()
    if "api_key" not in body or not body["api_key"]:
        body["api_key"] = f"shield-{body.get('username', 'user')}-{secrets.token_hex(12)}"
    new_user = User(**body)
    if any(u.username == new_user.username for u in config.users):
        raise HTTPException(status_code=409, detail=f"User '{new_user.username}' already exists")
    config.users.append(new_user)
    user_cache.clear()
    _save_config()
    return {"status": "created", "username": new_user.username, "api_key": new_user.api_key}


@app.delete("/admin/api/users/{username}")
async def admin_delete_user(
    username: str,
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    original_len = len(config.users)
    config.users = [u for u in config.users if u.username != username]
    if len(config.users) == original_len:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    user_cache.clear()
    _save_config()
    return {"status": "deleted", "username": username}


@app.get("/admin/api/audit")
async def admin_audit_log(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    limit: int = 50,
):
    _require_admin(x_api_key, request)
    return _tool_audit_summary(limit)


@app.get("/admin/api/sessions")
async def admin_sessions(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    return {
        "active": len(mcp_sessions),
        "sessions": [
            {
                "id": sid[:12] + "...",
                "client": s.get("client_info", {}).get("name", "unknown"),
                "initialized": s.get("initialized", False),
                "created_at": s.get("created_at", ""),
            }
            for sid, s in mcp_sessions.items()
        ],
    }


@app.post("/admin/api/reload")
async def admin_reload(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    await _reload_config()
    return {
        "status": "reloaded",
        "upstreams": len(config.upstream_servers),
        "users": len(config.users),
        "tools": len(tool_registry),
    }


@app.post("/admin/api/upstreams/rediscover")
async def admin_rediscover(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    _require_admin(x_api_key, request)
    await discover_all_upstreams()
    return {
        "status": "discovery_complete",
        "upstreams": {
            name: {"status": upstream_status.get(name, "unknown"), "tools": len(tools)}
            for name, tools in upstream_tools.items()
        },
    }


# ---------------------------------------------------------------------------
# Admin Dashboard
# ---------------------------------------------------------------------------

ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Shield</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e17;--surface:#111827;--surface2:#1e293b;--border:#334155;--text:#e2e8f0;--text2:#94a3b8;--accent:#3b82f6;--accent2:#60a5fa;--green:#22c55e;--red:#ef4444;--orange:#f59e0b;--purple:#a78bfa}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.login{display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;gap:16px}
.login h1{font-size:24px;color:var(--accent2)}
.login input{padding:12px 16px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text);width:320px;font-size:14px;outline:none}
.login input:focus{border-color:var(--accent)}
.login button{padding:12px 32px;border-radius:8px;border:none;background:var(--accent);color:#fff;cursor:pointer;font-size:14px;font-weight:600}
.login button:hover{background:var(--accent2)}
.login .error{color:var(--red);font-size:13px}
.app{display:none}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between}
header h1{font-size:18px;font-weight:600}
header h1 span{color:var(--accent2);font-weight:400;font-size:14px;margin-left:8px}
header .actions{display:flex;gap:8px;align-items:center}
.user-badge{background:var(--surface2);padding:4px 12px;border-radius:20px;font-size:12px;color:var(--accent2)}
.btn{padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--text);cursor:pointer;font-size:12px;display:inline-flex;align-items:center;gap:4px}
.btn:hover{border-color:var(--accent)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-danger{border-color:var(--red);color:var(--red)}
.btn-danger:hover{background:var(--red);color:#fff}
nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;gap:0}
nav button{padding:10px 20px;border:none;background:none;color:var(--text2);cursor:pointer;font-size:13px;border-bottom:2px solid transparent;transition:all .2s}
nav button:hover{color:var(--text)}
nav button.active{color:var(--accent2);border-bottom-color:var(--accent2)}
main{padding:24px;max-width:1200px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px}
.card .label{font-size:12px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.card .value{font-size:28px;font-weight:700}
.card .sub{font-size:12px;color:var(--text2);margin-top:4px}
.status{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.status.healthy,.status.connected{background:var(--green)}
.status.disconnected,.status.unhealthy{background:var(--red)}
.status.skipped,.status.unknown{background:var(--orange)}
table{width:100%;border-collapse:collapse;font-size:13px}
table th{text-align:left;padding:10px 12px;background:var(--surface2);color:var(--text2);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
table td{padding:10px 12px;border-bottom:1px solid var(--border)}
table tr:hover{background:var(--surface2)}
.section{margin-bottom:32px}
.section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.section h2{font-size:16px;font-weight:600}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;margin-right:4px}
.tag-admin{background:#7c3aed22;color:var(--purple)}
.tag-developer{background:#3b82f622;color:var(--accent2)}
.tag-analyst{background:#22c55e22;color:var(--green)}
.tag-contractor{background:#f59e0b22;color:var(--orange)}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.modal-bg.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;width:480px;max-width:90vw;max-height:80vh;overflow-y:auto}
.modal h3{margin-bottom:16px;font-size:16px}
.form-group{margin-bottom:12px}
.form-group label{display:block;font-size:12px;color:var(--text2);margin-bottom:4px}
.form-group input,.form-group select{width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:13px;outline:none}
.form-group input:focus,.form-group select:focus{border-color:var(--accent)}
.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.toast{position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:8px;font-size:13px;z-index:200;animation:slideIn .3s ease}
.toast-success{background:#22c55e;color:#fff}
.toast-error{background:#ef4444;color:#fff}
@keyframes slideIn{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.audit-entry{font-family:'SF Mono',Monaco,monospace;font-size:12px;padding:6px 0;border-bottom:1px solid var(--border)}
.audit-entry .ts{color:var(--text2)}
.audit-entry .user{color:var(--accent2)}
.audit-entry .method{color:var(--purple)}
.audit-entry .verdict-SUCCESS{color:var(--green)}
.audit-entry .verdict-PERMISSION_DENIED,.verdict-AUTH_FAILED,.verdict-RATE_LIMITED{color:var(--red)}
.empty{text-align:center;padding:40px;color:var(--text2)}
</style>
</head>
<body>

<div class="login" id="login">
  <h1>MCP Shield</h1>
  <input type="password" id="apiKeyInput" placeholder="Admin API Key" autofocus>
  <button onclick="doLogin()">Sign In</button>
  <div class="error" id="loginError"></div>
</div>

<div class="app" id="app">
  <header>
    <h1>MCP Gateway <span id="versionBadge"></span></h1>
    <div class="actions">
      <span class="user-badge" id="userBadge"></span>
      <button class="btn" onclick="reloadConfig()">Reload Config</button>
      <button class="btn" onclick="rediscover()">Rediscover</button>
      <button class="btn btn-danger" onclick="logout()">Logout</button>
    </div>
  </header>
  <nav>
    <button class="active" onclick="showTab(this,'overview')">Overview</button>
    <button onclick="showTab(this,'upstreams')">Upstreams</button>
    <button onclick="showTab(this,'users')">Users</button>
    <button onclick="showTab(this,'roles')">Roles &amp; Policies</button>
    <button onclick="showTab(this,'audit')">Audit Log</button>
    <button onclick="showTab(this,'sessions')">Sessions</button>
  </nav>
  <main>
    <div id="tab-overview"></div>
    <div id="tab-upstreams" style="display:none"></div>
    <div id="tab-users" style="display:none"></div>
    <div id="tab-roles" style="display:none"></div>
    <div id="tab-audit" style="display:none"></div>
    <div id="tab-sessions" style="display:none"></div>
  </main>
</div>

<div class="modal-bg" id="modalBg" onclick="if(event.target===this)closeModal()">
  <div class="modal" id="modalContent"></div>
</div>

<script>
let API_KEY='';
let DATA={};

function api(path,opts={}){
  return fetch('/admin/api/'+path,{
    ...opts,
    headers:{'X-API-Key':API_KEY,'Content-Type':'application/json',...(opts.headers||{})},
    body:opts.body?JSON.stringify(opts.body):undefined
  }).then(r=>{if(!r.ok)throw r;return r.json()});
}

function toast(msg,type='success'){
  const d=document.createElement('div');
  d.className='toast toast-'+type;
  d.textContent=msg;
  document.body.appendChild(d);
  setTimeout(()=>d.remove(),3000);
}

function showTab(btn,id){
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('main>div').forEach(d=>d.style.display='none');
  document.getElementById('tab-'+id).style.display='block';
  if(id==='audit')loadAudit();
  if(id==='sessions')loadSessions();
}

async function doLogin(){
  API_KEY=document.getElementById('apiKeyInput').value.trim();
  if(!API_KEY)return;
  try{
    DATA=await api('overview');
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    render();
  }catch(e){
    document.getElementById('loginError').textContent='Invalid admin key';
  }
}
document.getElementById('apiKeyInput').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});

function logout(){API_KEY='';document.getElementById('app').style.display='none';document.getElementById('login').style.display='flex';document.getElementById('apiKeyInput').value='';}

async function refresh(){DATA=await api('overview');render();}

function render(){
  document.getElementById('versionBadge').textContent='v'+DATA.version+' • MCP '+DATA.protocol_version;
  const admin=DATA.users.find(u=>u.roles.includes('admin'));
  document.getElementById('userBadge').textContent=admin?admin.username:'admin';
  renderOverview();renderUpstreams();renderUsers();renderRoles();
}

function renderOverview(){
  const u=DATA.upstreams;
  const connected=u.filter(x=>x.status==='connected').length;
  const totalTools=DATA.total_tools;
  document.getElementById('tab-overview').innerHTML=`
    <div class="grid">
      <div class="card"><div class="label">Upstreams</div><div class="value">${u.length}</div><div class="sub">${connected} connected</div></div>
      <div class="card"><div class="label">Total Tools</div><div class="value">${totalTools}</div><div class="sub">Across all upstreams</div></div>
      <div class="card"><div class="label">Users</div><div class="value">${DATA.users.length}</div><div class="sub">${Object.keys(DATA.roles).length} roles</div></div>
      <div class="card"><div class="label">Active Sessions</div><div class="value">${DATA.sessions}</div><div class="sub">MCP clients connected</div></div>
      <div class="card"><div class="label">Rate Limit</div><div class="value">${DATA.rate_limit.requests_per_minute||'--'}/min</div><div class="sub">${DATA.rate_limit.enabled?'Enabled':'Disabled'}</div></div>
      <div class="card"><div class="label">Policies</div><div class="value">${DATA.policies.argument_guards+DATA.policies.output_redaction}</div><div class="sub">${DATA.policies.argument_guards} guards, ${DATA.policies.output_redaction} DLP rules</div></div>
    </div>
    <div class="section"><h2>Upstream Status</h2>
    <table><tr><th>Name</th><th>Type</th><th>URL</th><th>Status</th><th>Tools</th><th>Timeout</th></tr>
    ${u.map(s=>`<tr><td><strong>${s.name}</strong><br><span style="color:var(--text2);font-size:11px">${s.description||''}</span></td><td>${s.type}</td><td style="font-family:monospace;font-size:12px">${s.url}</td><td><span class="status ${s.status}"></span>${s.status}</td><td>${s.tools}</td><td>${s.timeout_seconds}s</td></tr>`).join('')}
    </table></div>`;
}

function renderUpstreams(){
  const u=DATA.upstreams;
  document.getElementById('tab-upstreams').innerHTML=`
    <div class="section"><div class="section-header"><h2>Upstream Servers</h2><button class="btn btn-primary" onclick="showAddUpstream()">+ Add Upstream</button></div>
    <table><tr><th>Name</th><th>Type</th><th>URL</th><th>Status</th><th>Tools</th><th>Actions</th></tr>
    ${u.map(s=>`<tr><td><strong>${s.name}</strong></td><td>${s.type}</td><td style="font-family:monospace;font-size:12px">${s.url}</td><td><span class="status ${s.status}"></span>${s.status}</td><td>${s.tools}</td>
    <td><button class="btn btn-danger" onclick="deleteUpstream('${s.name}')">Delete</button></td></tr>`).join('')}
    </table></div>`;
}

function showAddUpstream(){
  document.getElementById('modalContent').innerHTML=`
    <h3>Add Upstream Server</h3>
    <div class="form-group"><label>Name</label><input id="f-name" placeholder="my_server"></div>
    <div class="form-group"><label>Type</label><select id="f-type"><option value="sse">SSE (HTTP)</option><option value="stdio">Stdio</option></select></div>
    <div class="form-group"><label>URL</label><input id="f-url" placeholder="http://localhost:8080/sse"></div>
    <div class="form-group"><label>Description</label><input id="f-desc" placeholder="What this server does"></div>
    <div class="form-group"><label>Timeout (seconds)</label><input id="f-timeout" type="number" value="30"></div>
    <div class="form-actions"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitUpstream()">Add</button></div>`;
  openModal();
}

async function submitUpstream(){
  const body={name:g('f-name'),type:g('f-type'),url:g('f-url')||null,description:g('f-desc'),timeout_seconds:parseInt(g('f-timeout'))||30};
  try{await api('upstreams',{method:'POST',body});toast('Upstream added');closeModal();await refresh();}catch(e){toast('Failed: '+(await e.text?.()|| 'error'),'error');}
}

async function deleteUpstream(name){
  if(!confirm('Delete upstream "'+name+'"?'))return;
  try{await api('upstreams/'+name,{method:'DELETE'});toast('Upstream deleted');await refresh();}catch(e){toast('Failed','error');}
}

function renderUsers(){
  document.getElementById('tab-users').innerHTML=`
    <div class="section"><div class="section-header"><h2>Users</h2><button class="btn btn-primary" onclick="showAddUser()">+ Add User</button></div>
    <table><tr><th>Username</th><th>Roles</th><th>Email</th><th>Department</th><th>API Key</th><th>Actions</th></tr>
    ${DATA.users.map(u=>`<tr><td><strong>${u.username}</strong></td><td>${u.roles.map(r=>'<span class="tag tag-'+r+'">'+r+'</span>').join('')}</td><td>${u.email}</td><td>${u.department}</td><td style="font-family:monospace;font-size:12px">${u.api_key_preview}</td>
    <td><button class="btn btn-danger" onclick="deleteUser('${u.username}')">Delete</button></td></tr>`).join('')}
    </table></div>`;
}

function showAddUser(){
  const roles=Object.keys(DATA.roles);
  document.getElementById('modalContent').innerHTML=`
    <h3>Add User</h3>
    <div class="form-group"><label>Username</label><input id="f-username" placeholder="johndoe"></div>
    <div class="form-group"><label>Email</label><input id="f-email" placeholder="john@mcp_shield.com"></div>
    <div class="form-group"><label>Department</label><input id="f-dept" placeholder="engineering"></div>
    <div class="form-group"><label>Role</label><select id="f-role">${roles.map(r=>'<option value="'+r+'">'+r+'</option>').join('')}</select></div>
    <div class="form-group"><label>API Key (leave blank to auto-generate)</label><input id="f-apikey" placeholder="auto-generated"></div>
    <div class="form-actions"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitUser()">Add</button></div>`;
  openModal();
}

async function submitUser(){
  const body={username:g('f-username'),email:g('f-email'),department:g('f-dept'),roles:[g('f-role')],api_key:g('f-apikey')||undefined};
  try{const r=await api('users',{method:'POST',body});toast('User created. Key: '+r.api_key);closeModal();await refresh();}catch(e){toast('Failed','error');}
}

async function deleteUser(name){
  if(!confirm('Delete user "'+name+'"?'))return;
  try{await api('users/'+name,{method:'DELETE'});toast('User deleted');await refresh();}catch(e){toast('Failed','error');}
}

function renderRoles(){
  const roles=DATA.roles;
  document.getElementById('tab-roles').innerHTML=`
    <div class="section"><h2>Roles</h2>
    <table><tr><th>Role</th><th>Description</th><th>Allow</th><th>Deny</th></tr>
    ${Object.entries(roles).map(([name,r])=>{
      const allows=r.permissions.filter(p=>p.allow).map(p=>'<code>'+p.allow+'</code>').join(', ')||'—';
      const denies=r.permissions.filter(p=>p.deny).map(p=>'<code>'+p.deny+'</code>').join(', ')||'—';
      return `<tr><td><span class="tag tag-${name}">${name}</span></td><td>${r.description}</td><td>${allows}</td><td style="color:var(--red)">${denies}</td></tr>`;
    }).join('')}
    </table></div>
    <div class="section"><h2>Security Policies</h2>
    <div class="grid">
      <div class="card"><div class="label">Argument Guards</div><div class="value">${DATA.policies.argument_guards}</div><div class="sub">Input validation rules</div></div>
      <div class="card"><div class="label">DLP Rules</div><div class="value">${DATA.policies.output_redaction}</div><div class="sub">Output redaction patterns</div></div>
    </div></div>`;
}

async function loadAudit(){
  try{
    const d=await api('audit?limit=100');
    const entries=(d.recent||[]).reverse();
    document.getElementById('tab-audit').innerHTML=`
      <div class="section"><div class="section-header"><h2>Audit Log</h2><span style="color:var(--text2);font-size:13px">${d.total_entries} total entries</span></div>
      ${entries.length?entries.map(e=>`<div class="audit-entry"><span class="ts">${e.timestamp?.substring(11,19)||''}</span> <span class="user">${e.user}</span> <span class="method">${e.method}</span>${e.tool?' → <strong>'+e.tool+'</strong>':''} <span class="verdict-${e.policy_verdict}">${e.policy_verdict}</span>${e.upstream_latency_ms?' <span style="color:var(--text2)">('+e.upstream_latency_ms+'ms)</span>':''}${e.redacted_pii_count?' <span style="color:var(--orange)">'+e.redacted_pii_count+' redacted</span>':''}${e.error?' <span style="color:var(--red)">'+e.error+'</span>':''}</div>`).join(''):'<div class="empty">No audit entries yet</div>'}
      </div>`;
  }catch(e){document.getElementById('tab-audit').innerHTML='<div class="empty">Failed to load audit log</div>';}
}

async function loadSessions(){
  try{
    const d=await api('sessions');
    document.getElementById('tab-sessions').innerHTML=`
      <div class="section"><h2>Active Sessions (${d.active})</h2>
      ${d.sessions.length?`<table><tr><th>Session ID</th><th>Client</th><th>Initialized</th><th>Created</th></tr>
      ${d.sessions.map(s=>`<tr><td style="font-family:monospace">${s.id}</td><td>${s.client}</td><td>${s.initialized?'<span style="color:var(--green)">Yes</span>':'<span style="color:var(--orange)">Pending</span>'}</td><td>${s.created_at?.substring(0,19)||''}</td></tr>`).join('')}
      </table>`:'<div class="empty">No active MCP sessions</div>'}
      </div>`;
  }catch(e){document.getElementById('tab-sessions').innerHTML='<div class="empty">Failed to load sessions</div>';}
}

async function reloadConfig(){
  try{const r=await api('reload',{method:'POST'});toast('Config reloaded: '+r.upstreams+' upstreams, '+r.users+' users');await refresh();}catch(e){toast('Reload failed','error');}
}

async function rediscover(){
  try{const r=await api('upstreams/rediscover',{method:'POST'});toast('Discovery complete');await refresh();}catch(e){toast('Discovery failed','error');}
}

function g(id){return document.getElementById(id).value.trim();}
function openModal(){document.getElementById('modalBg').classList.add('open');}
function closeModal(){document.getElementById('modalBg').classList.remove('open');}
</script>
</body>
</html>"""


@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard():
    return ADMIN_HTML
