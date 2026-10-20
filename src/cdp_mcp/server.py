import asyncio
import base64
import json
import pathlib
import re
import threading
from typing import Optional
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

    return mcp
