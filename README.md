<p align="center">
  <h1 align="center">🛡️ AgentWacht</h1>
  <p align="center"><strong>Zero Trust proxy for the Model Context Protocol</strong></p>
  <p align="center">
    <a href="#quickstart">Quickstart</a> •
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#deployment">Deployment</a>
  </p>
</p>

---

**AgentWacht** is an open-source security gateway that sits between AI agents and the tools they access via [MCP (Model Context Protocol)](https://modelcontextprotocol.io). It enforces Zero Trust policies on every tool call — authentication, RBAC, argument validation, output redaction, and full audit logging.

> **Why?** Multi-agent AI systems create N² attack paths. Every agent can call every tool, pass untrusted arguments, and leak sensitive data. AgentWacht gives you a single enforcement point with policy-as-code.

## Features

| Layer | Capability |
|-------|-----------|
| **Authentication** | API key verification, session management |
| **RBAC** | Role-based access control with glob patterns, deny-takes-precedence |
| **Argument Validation** | Regex guards against SQL injection, path traversal, shell injection |
| **DLP / Output Redaction** | PII stripping (SSN, credit cards, emails, phone numbers, API keys, AWS creds) |
| **Audit Trail** | Immutable JSONL logging with args hash, latency, verdict, PII redaction count |
| **Rate Limiting** | Per-user requests-per-minute with burst support |
| **Multi-Upstream** | Aggregate tools from multiple MCP servers (SSE + Stdio) |
| **Protocol** | MCP 2024-11-05 through 2025-11-25, auto-negotiation |
| **Admin Dashboard** | Built-in web UI for managing upstreams, users, roles, audit |

## Quickstart

### Option 1: Python

```bash
git clone https://github.com/8peaks/agentwacht.git
cd agentwacht
pip install -r requirements.txt
python run_gateway.py
```

The gateway starts on `http://localhost:8000`. Open `http://localhost:8000/admin` for the dashboard.

### Option 2: Docker

```bash
git clone https://github.com/8peaks/agentwacht.git
cd agentwacht
docker compose up -d
```

### Option 3: Make

```bash
make install
make run
# or
make dev  # auto-reload mode
```

## Architecture

```
┌─────────────────┐     ┌──────────────────────────────────┐     ┌──────────────┐
│   AI Workflows   │     │         AgentWacht               │     │  MCP Servers  │
│                  │     │                                  │     │              │
│  Chatbots        │────▶│  1. Authentication               │────▶│  Databases   │
│  Code Agents     │     │  2. RBAC Check                   │     │  File System │
│  Data Pipelines  │     │  3. Argument Validation          │     │  GitHub      │
│  Copilots        │◁───│  4. Upstream Execution            │◁───│  APIs        │
│                  │     │  5. Output DLP Redaction          │     │  Analytics   │
│                  │     │  6. Audit Logging                 │     │              │
└─────────────────┘     └──────────────────────────────────┘     └──────────────┘
```

Every tool call passes through all 5 enforcement layers. No exceptions.

## Configuration

All security policies are defined in `policy.yaml`:

### Upstream Servers

```yaml
upstream_servers:
  - name: my_database
    type: sse
    url: http://localhost:8080/sse
    description: "Production database"
    health_check_path: /health
    timeout_seconds: 30
```

### Users & Roles

```yaml
users:
  - username: alice
    api_key: my-secret-key
    roles: [developer]
    email: alice@example.com
    department: engineering

roles:
  developer:
    description: "Access to dev tools"
    permissions:
      - allow: "my_database_*"
      - deny: "my_database_drop*"
```

### Argument Guards

```yaml
policies:
  argument_guards:
    - tool_pattern: "*_db_*"
      argument_name: "query"
      validation_type: regex_deny
      regex: "(?i)(DROP\\s+TABLE|DELETE\\s+FROM|UNION\\s+SELECT)"
      error_message: "SQL injection detected"
```

### DLP / Output Redaction

```yaml
policies:
  output_redaction:
    - pattern_type: credit_card
      regex: "\\b[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b"
      replacement: "[CARD_REDACTED]"
      applies_to_tools: ["*"]
      except_roles: ["admin"]
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp` | MCP Streamable HTTP (JSON-RPC 2.0) |
| `GET` | `/mcp` | SSE stream for server-initiated messages |
| `DELETE` | `/mcp` | Terminate MCP session |
| `GET` | `/health` | Health check + upstream status |
| `GET` | `/admin` | Admin dashboard (web UI) |
| `POST` | `/tools/list` | Legacy REST: list tools |
| `POST` | `/tools/call` | Legacy REST: call tool |

### Admin API (requires admin role)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/api/overview` | Full system overview |
| `GET/POST/PUT/DELETE` | `/admin/api/upstreams` | CRUD upstream servers |
| `GET/POST/DELETE` | `/admin/api/users` | CRUD users |
| `GET` | `/admin/api/audit` | Query audit log |
| `GET` | `/admin/api/sessions` | Active MCP sessions |
| `POST` | `/admin/api/reload` | Hot-reload config |
| `POST` | `/admin/api/upstreams/rediscover` | Re-discover upstream tools |

## Testing

```bash
# Start the gateway first, then:
python test_gateway.py

# Or with custom host/port:
python test_gateway.py --host localhost --port 8000
```

The test suite covers: health check, MCP initialize/tools flow, RBAC enforcement, argument validation (SQL injection, path traversal), DLP redaction, rate limiting, session management, and admin API.

## Deployment

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_PORT` | `8000` | Port to listen on |
| `GATEWAY_HOST` | `0.0.0.0` | Host to bind to |
| `GATEWAY_CONFIG` | `policy.yaml` | Path to config file |

### Production Recommendations

- Run behind a reverse proxy (nginx, Caddy) with TLS
- Use strong, unique API keys (not the demo keys)
- Mount `policy.yaml` as read-only volume in Docker
- Enable rate limiting in production
- Ship audit logs to your SIEM (JSONL format)
- Restrict admin role to ops team only

## EU AI Act Compliance

AgentWacht helps organisations meet EU AI Act requirements for high-risk AI systems:

- **Article 9 (Risk Management)**: Argument validation prevents dangerous tool calls
- **Article 12 (Record-Keeping)**: Immutable audit trail with 90-day retention
- **Article 14 (Human Oversight)**: Admin dashboard for real-time monitoring
- **Article 15 (Accuracy/Robustness)**: DLP prevents data leakage

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## About

Built by [8peaks](https://8peaks.io) — AI security for sovereign Europe.

Antwerp, Belgium 🇧🇪 | [info@8peaks.io](mailto:info@8peaks.io)
