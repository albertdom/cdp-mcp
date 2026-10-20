# cdp-mcp

MCP server that embeds mitmproxy to give Claude full HTTP/HTTPS traffic interception capabilities — like Burp Suite, but driven by natural language.

## Setup

```powershell
cd C:\Users\domen\cdp-mcp
uv sync
```

## Claude Desktop configuration

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cdp-mcp": {
      "command": "uv",
      "args": ["run", "cdp-mcp"],
      "cwd": "C:\\Users\\domen\\cdp-mcp"
    }
  }
}
```

## First use

1. Ask Claude: **"Start the proxy"** → Claude calls `start_proxy()`
2. Install the CA certificate (instructions returned by the tool)
3. Configure your browser: proxy = `127.0.0.1:8080`
4. Browse your target app
5. Ask Claude: **"List the last 20 flows"**, **"Find any exposed JWTs"**, **"Replay that POST to /api/login with Authorization: Bearer xyz"**

## CA certificate installation (for HTTPS interception)

Run `start_proxy()` once — mitmproxy generates `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem` automatically.

Install in Windows (PowerShell as admin):
```powershell
Import-Certificate -FilePath "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.pem" -CertStoreLocation Cert:\LocalMachine\Root
```

Install in Chrome/Edge: Settings → Privacy → Manage certificates → Trusted Root CAs → Import

Install in Firefox: Settings → Privacy → Certificates → View Certificates → Authorities → Import

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CDP_MCP_DB_PATH` | `~/.cdp-mcp/flows.db` | SQLite database path |

## Available tools (14 total)

| Tool | Description |
|------|-------------|
| `start_proxy(port?)` | Start proxy on port (default 8080), returns cert install instructions |
| `stop_proxy()` | Stop the proxy |
| `get_proxy_status()` | Running state, port, and flow count |
| `list_flows(host?, path?, method?, status_code?, limit?)` | Filter captured flows |
| `get_flow(flow_id)` | Full request + response detail |
| `search_flows(query)` | Free-text search across URL, headers, body |
| `replay_flow(flow_id, modifications?)` | Resend a captured request with optional changes |
| `fuzz_flow(flow_id, field, values[])` | Repeat with varying field (query.X, header.X, or body) |
| `enable_intercept(filter?)` | Pause outgoing requests matching filter |
| `get_intercepted()` | List paused requests awaiting decision |
| `release_flow(flow_id, modifications?)` | Forward intercepted request |
| `drop_flow(flow_id)` | Discard intercepted request |
| `analyze_flow(flow_id)` | Security analysis: JWTs, missing headers, sensitive data, SQLi |
| `export_flow(flow_id, format)` | Export as `curl`, `python` script, or `burp` XML |

## Example session

```
User: Start the proxy on port 8080
Claude: [calls start_proxy(8080)] Proxy started. Install the CA cert at ~/.mitmproxy/mitmproxy-ca-cert.pem, then configure your browser to use 127.0.0.1:8080.

User: I've browsed the login page. Show me all POST requests
Claude: [calls list_flows(method="POST")] Found 3 POST requests...

User: Analyze the login request for security issues
Claude: [calls analyze_flow("flow-id-here")] Found: exposed JWT in response body, missing X-Frame-Options header...

User: Replay that login request with a different password
Claude: [calls replay_flow("flow-id", modifications={"body": '{"user":"admin","pass":"test123"}'})] Response: 401 Unauthorized
```
