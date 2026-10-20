"""Standalone mitmproxy runner — launched as a subprocess by ProxyState."""
import asyncio
import json
import sys
import os

_IGNORE_HOSTS = [
    r".*\.anthropic\.com",
    r".*\.claude\.ai",
    r"api\.anthropic\.com",
    r"statsig\.anthropic\.com",
    r"sentry\.io",
]


def main():
    if len(sys.argv) < 3:
        sys.exit("Usage: runner.py <db_path> <port>")

    db_path = sys.argv[1]
    port = int(sys.argv[2])

    from cdp_mcp.store import FlowStore
    from cdp_mcp.proxy import FlowStoreAddon

    store = FlowStore(db_path)
    addon = FlowStoreAddon(store)

    class ReadySignal:
        """Addon that signals the parent process when mitmproxy is listening."""
        def running(self):
            sys.stderr.write("READY\n")
            sys.stderr.flush()

    async def amain():
        from mitmproxy import options
        from mitmproxy.tools import dump

        opts = options.Options(
            listen_host="127.0.0.1",
            listen_port=port,
            ignore_hosts=_IGNORE_HOSTS,
            ssl_insecure=True,
        )
        master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(ReadySignal())
        master.addons.add(addon)
        await master.run()

    asyncio.run(amain())


if __name__ == "__main__":
    main()
