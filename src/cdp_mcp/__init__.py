import asyncio
import os
import pathlib
import threading
from cdp_mcp.store import FlowStore
from cdp_mcp.proxy import FlowStoreAddon
from cdp_mcp.server import create_server


def _get_db_path() -> str:
    default = pathlib.Path.home() / ".cdp-mcp" / "flows.db"
    path = pathlib.Path(os.environ.get("CDP_MCP_DB_PATH", str(default)))
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def main():
    db_path = _get_db_path()
    store = FlowStore(db_path)
    addon = FlowStoreAddon(store)
    mcp = create_server(store, addon)
    mcp.run()
