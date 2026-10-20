import asyncio
import base64
import json
import pathlib
import re
import threading
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import requests as http_requests
from mcp.server.fastmcp import FastMCP
from cdp_mcp.store import FlowStore
from cdp_mcp.proxy import FlowStoreAddon


CERT_INSTALL_INSTRUCTIONS = """
CA certificate generated at: ~/.mitmproxy/mitmproxy-ca-cert.pem

Install instructions:
  Chrome/Edge (Windows): Settings → Privacy → Manage certificates → Trusted Root CAs → Import
  Firefox: Settings → Privacy → Certificates → View Certificates → Authorities → Import
  System (Windows PowerShell as admin):
    Import-Certificate -FilePath "$env:USERPROFILE\\.mitmproxy\\mitmproxy-ca-cert.pem" -CertStoreLocation Cert:\\LocalMachine\\Root

Then configure your browser/app to use proxy: 127.0.0.1:{port}
"""


class ProxyState:
    def __init__(self):
        self.running = False
        self.port: Optional[int] = None
        self._master = None
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def status(self, store: FlowStore) -> dict:
        count = store.count() if self.running else 0
        return {
            "running": self.running,
            "port": self.port,
            "flow_count": count,
        }

    def start(self, store: FlowStore, addon: FlowStoreAddon, port: int = 8080) -> dict:
        if self.running:
            return {"error": f"Proxy already running on port {self.port}"}

        ready_event = threading.Event()
        error_holder = []

        def run():
            from mitmproxy import options
            from mitmproxy.tools import dump

            async def amain():
                opts = options.Options(
                    listen_host="127.0.0.1",
                    listen_port=port,
                )
                master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
                master.addons.add(addon)
                self._master = master
                self._loop = asyncio.get_running_loop()
                addon._loop = self._loop
                self.running = True
                self.port = port
                ready_event.set()
                try:
                    await master.run()
                except Exception as e:
                    error_holder.append(str(e))
                finally:
                    self.running = False

            asyncio.run(amain())

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        ready_event.wait(timeout=5)

        if not ready_event.is_set():
            return {"error": "Proxy startup timed out after 5 seconds"}
        if error_holder:
            return {"error": error_holder[0]}

        return {
            "started": True,
            "port": port,
            "cert_instructions": CERT_INSTALL_INSTRUCTIONS.format(port=port),
        }

    def stop(self) -> dict:
        if not self.running:
            return {"error": "Proxy is not running"}
        if self._master:
            self._master.shutdown()
        if self._thread:
            self._thread.join(timeout=3)
        self.running = False
        self._master = None
        self._thread = None
        return {"stopped": True}


def _schedule_resume(flow, loop, modifications: dict = None):
    if modifications and "body" in modifications:
        body = modifications["body"]
        flow.request.content = body.encode() if isinstance(body, str) else body
    if modifications and "headers" in modifications:
        flow.request.headers.update(modifications["headers"])
    if loop:
        asyncio.run_coroutine_threadsafe(flow.resume(), loop)
    else:
        flow.resume()


def _schedule_drop(flow, _loop=None):
    flow.kill()


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SENSITIVE_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[=:\"]+\s*\S+",
    re.IGNORECASE,
)
_SQLI_RE = re.compile(r"(\bOR\b\s+\d+=\d+|--|;DROP|UNION\s+SELECT)", re.IGNORECASE)
_SECURITY_HEADERS = [
    "x-frame-options", "x-content-type-options", "content-security-policy",
    "strict-transport-security", "x-xss-protection", "referrer-policy",
]


def _analyze(record: dict) -> list:
    findings = []
    all_text = " ".join([
        record.get("path", ""),
        record.get("query", ""),
        (record.get("req_body") or b"").decode("utf-8", errors="ignore"),
        (record.get("res_body") or b"").decode("utf-8", errors="ignore"),
        record.get("req_headers", ""),
        record.get("res_headers", ""),
    ])
    res_headers_lower = {k.lower(): v for k, v in json.loads(record.get("res_headers") or "{}").items()}

    for match in _JWT_RE.finditer(all_text):
        findings.append({"type": "exposed_jwt", "severity": "medium",
                         "detail": f"JWT token found: {match.group()[:40]}..."})

    for h in _SECURITY_HEADERS:
        if h not in res_headers_lower:
            findings.append({"type": "missing_security_header", "severity": "low",
                             "detail": f"Missing response header: {h}"})

    for match in _SENSITIVE_RE.finditer(all_text):
        findings.append({"type": "sensitive_data", "severity": "high",
                         "detail": f"Possible sensitive field: {match.group()[:60]}"})

    for match in _SQLI_RE.finditer(record.get("query", "") + " " + (record.get("req_body") or b"").decode("utf-8", errors="ignore")):
        findings.append({"type": "sqli_pattern", "severity": "high",
                         "detail": f"Possible SQLi pattern: {match.group()}"})

    return findings


def _sh_escape(s: str) -> str:
    """Escape single quotes in a string for use in single-quoted shell strings."""
    return s.replace("'", "'\"'\"'")


def _export_curl(record: dict) -> str:
    headers = json.loads(record.get("req_headers") or "{}")
    url = f"{record['scheme']}://{record['host']}:{record['port']}{record['path']}"
    if record.get("query"):
        url += f"?{record['query']}"
    parts = [f"curl -X {record['method']} '{_sh_escape(url)}'"]
    for k, v in headers.items():
        parts.append(f"  -H '{_sh_escape(k)}: {_sh_escape(str(v))}'")
    body = record.get("req_body") or b""
    if body:
        body_str = body.decode("utf-8", errors="replace")
        parts.append(f"  -d '{_sh_escape(body_str)}'")
    parts.append("  --proxy 'http://127.0.0.1:8080' --insecure")
    return " \\\n".join(parts)


def _export_python(record: dict) -> str:
    headers = json.loads(record.get("req_headers") or "{}")
    url = f"{record['scheme']}://{record['host']}:{record['port']}{record['path']}"
    if record.get("query"):
        url += f"?{record['query']}"
    body = record.get("req_body") or b""
    body_repr = repr(body.decode("utf-8", errors="replace")) if body else "None"
    return f"""import requests

response = requests.{record['method'].lower()}(
    "{url}",
    headers={json.dumps(headers, indent=4)},
    data={body_repr},
    verify=False,
)
print(response.status_code, response.text)
"""


def _export_burp_xml(record: dict) -> str:
    import xml.etree.ElementTree as ET
    root = ET.Element("items", burpVersion="2023.1")
    item = ET.SubElement(root, "item")
    ET.SubElement(item, "time").text = str(record["timestamp"])
    ET.SubElement(item, "url").text = f"{record['scheme']}://{record['host']}:{record['port']}{record['path']}"
    ET.SubElement(item, "host", ip="").text = record["host"]
    ET.SubElement(item, "port").text = str(record["port"])
    ET.SubElement(item, "protocol").text = record["scheme"]
    ET.SubElement(item, "method").text = record["method"]
    ET.SubElement(item, "path").text = record["path"]
    req_b64 = base64.b64encode(record.get("req_body") or b"").decode()
    ET.SubElement(item, "request", base64="true").text = req_b64
    res_b64 = base64.b64encode(record.get("res_body") or b"").decode()
    ET.SubElement(item, "response", base64="true").text = res_b64
    ET.SubElement(item, "status").text = str(record.get("res_status", ""))
    return ET.tostring(root, encoding="unicode")


def create_server(store: FlowStore, addon: FlowStoreAddon) -> FastMCP:
    mcp = FastMCP("cdp-mcp")
    state = ProxyState()

    @mcp.tool()
    def start_proxy(port: int = 8080) -> dict:
        """Start the mitmproxy HTTP/HTTPS proxy on the given port."""
        return state.start(store, addon, port)

    @mcp.tool()
    def stop_proxy() -> dict:
        """Stop the running proxy."""
        return state.stop()

    @mcp.tool()
    def get_proxy_status() -> dict:
        """Get current proxy state: running, port, number of captured flows."""
        return state.status(store)

    def _decode_body(body: bytes) -> str:
        if not body:
            return ""
        try:
            return body.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            return base64.b64encode(body).decode()

    def _format_flow(record: dict) -> dict:
        return {
            **record,
            "req_body": _decode_body(record.get("req_body") or b""),
            "res_body": _decode_body(record.get("res_body") or b""),
            "req_headers": json.loads(record.get("req_headers") or "{}"),
            "res_headers": json.loads(record.get("res_headers") or "{}"),
            "tags": json.loads(record.get("tags") or "[]"),
        }

    @mcp.tool()
    def list_flows(
        host: str = None,
        path: str = None,
        method: str = None,
        status_code: int = None,
        limit: int = 100,
    ) -> list:
        """List captured HTTP flows with optional filters."""
        rows = store.list_flows(host=host, path=path, method=method,
                                status_code=status_code, limit=limit)
        return [_format_flow(r) for r in rows]

    @mcp.tool()
    def get_flow(flow_id: str) -> dict:
        """Get full detail of a captured flow by ID."""
        record = store.get(flow_id)
        if record is None:
            return {"error": f"Flow '{flow_id}' not found"}
        return _format_flow(record)

    @mcp.tool()
    def search_flows(query: str) -> list:
        """Search flows by free text across URL, headers, and body."""
        rows = store.search(query)
        return [_format_flow(r) for r in rows]

    def _apply_modifications(url: str, headers: dict, body: bytes, modifications: dict) -> tuple:
        if not modifications:
            return url, headers, body
        if "headers" in modifications:
            headers = {**headers, **modifications["headers"]}
        if "body" in modifications:
            body = modifications["body"].encode() if isinstance(modifications["body"], str) else modifications["body"]
        if "path" in modifications:
            parsed = urlparse(url)
            url = urlunparse(parsed._replace(path=modifications["path"]))
        if "query" in modifications:
            parsed = urlparse(url)
            existing = parse_qs(parsed.query, keep_blank_values=True)
            existing.update({k: [v] for k, v in modifications["query"].items()})
            url = urlunparse(parsed._replace(query=urlencode(existing, doseq=True)))
        return url, headers, body

    def _do_request(record: dict, modifications: dict = None) -> dict:
        headers = json.loads(record.get("req_headers") or "{}")
        body = record.get("req_body") or b""
        url = f"{record['scheme']}://{record['host']}:{record['port']}{record['path']}"
        if record.get("query"):
            url += f"?{record['query']}"
        url, headers, body = _apply_modifications(url, headers, body, modifications or {})
        resp = http_requests.request(
            record["method"], url, headers=headers, data=body, verify=False, timeout=30
        )
        store.update(record["id"], replayed=1)
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": _decode_body(resp.content),
            "url": url,
        }

    @mcp.tool()
    def replay_flow(flow_id: str, modifications: dict = None) -> dict:
        """Replay a captured request. Optional modifications dict: {headers, body, path, query}."""
        record = store.get(flow_id)
        if record is None:
            return {"error": f"Flow '{flow_id}' not found"}
        return _do_request(record, modifications)

    @mcp.tool()
    def fuzz_flow(flow_id: str, field: str, values: list) -> list:
        """Replay a flow N times, varying one field each time.
        field format: 'query.param', 'header.Name', or 'body'.
        Returns list of responses."""
        record = store.get(flow_id)
        if record is None:
            return [{"error": f"Flow '{flow_id}' not found"}]
        results = []
        for value in values:
            if field.startswith("query."):
                param = field[len("query."):]
                mods = {"query": {param: value}}
            elif field.startswith("header."):
                header = field[len("header."):]
                mods = {"headers": {header: value}}
            else:
                mods = {"body": value}
            resp = _do_request(record, mods)
            resp["fuzz_value"] = value
            results.append(resp)
        return results

    @mcp.tool()
    def enable_intercept(filter: str = None) -> dict:
        """Enable active interception. Requests matching filter (substring of host) are paused.
        Pass no filter to intercept all requests."""
        addon.set_intercept_filter(filter)
        return {"intercept_enabled": True, "filter": filter}

    @mcp.tool()
    def get_intercepted() -> list:
        """Return list of currently intercepted (paused) flows awaiting a decision."""
        return addon.get_intercepted_flows()

    @mcp.tool()
    def release_flow(flow_id: str, modifications: dict = None) -> dict:
        """Forward an intercepted flow, optionally with modifications {headers, body}."""
        flow = addon.intercepted_flows.get(flow_id)
        if flow is None:
            return {"error": f"No intercepted flow with id '{flow_id}'"}
        _schedule_resume(flow, getattr(addon, "_loop", None), modifications)
        del addon.intercepted_flows[flow_id]
        return {"released": True, "flow_id": flow_id}

    @mcp.tool()
    def drop_flow(flow_id: str) -> dict:
        """Discard an intercepted flow (never forwarded to server)."""
        flow = addon.intercepted_flows.get(flow_id)
        if flow is None:
            return {"error": f"No intercepted flow with id '{flow_id}'"}
        _schedule_drop(flow, getattr(addon, "_loop", None))
        del addon.intercepted_flows[flow_id]
        return {"dropped": True, "flow_id": flow_id}

    @mcp.tool()
    def analyze_flow(flow_id: str) -> dict:
        """Analyze a flow for security issues: exposed JWTs, missing headers, sensitive data, SQLi patterns."""
        record = store.get(flow_id)
        if record is None:
            return {"error": f"Flow '{flow_id}' not found"}
        findings = _analyze(record)
        return {
            "flow_id": flow_id,
            "url": f"{record['scheme']}://{record['host']}{record['path']}",
            "findings": findings,
            "finding_count": len(findings),
        }

    @mcp.tool()
    def export_flow(flow_id: str, format: str = "curl") -> dict:
        """Export a flow as curl command, Python requests script, or Burp XML.
        format: 'curl' | 'python' | 'burp'"""
        record = store.get(flow_id)
        if record is None:
            return {"error": f"Flow '{flow_id}' not found"}
        if format == "curl":
            return {"format": "curl", "output": _export_curl(record)}
        elif format == "python":
            return {"format": "python", "output": _export_python(record)}
        elif format == "burp":
            return {"format": "burp", "output": _export_burp_xml(record)}
        else:
            return {"error": f"Unknown format '{format}'. Use: curl, python, burp"}

    return mcp
