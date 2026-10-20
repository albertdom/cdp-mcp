# cdp-mcp

MCP server for HTTP/HTTPS traffic interception and pentesting via mitmproxy.

## Features

- Embeds mitmproxy as a local HTTP/HTTPS proxy (port 8080 by default)
- Captures all HTTP/HTTPS traffic to a SQLite database
- Exposes tools to Claude via MCP for traffic analysis, interception, replay, and fuzzing

## Installation

```bash
uv sync
```

## Usage

```bash
cdp-mcp
```
