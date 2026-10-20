"""Smoke test: verify all 17 tools are registered."""
from unittest.mock import MagicMock
from cdp_mcp.store import FlowStore
from cdp_mcp.proxy import FlowStoreAddon
from cdp_mcp.server import create_server

EXPECTED_TOOLS = {
    "start_proxy", "stop_proxy", "get_proxy_status",
    "list_flows", "get_flow", "search_flows",
    "replay_flow", "fuzz_flow",
    "enable_intercept", "get_intercepted", "release_flow", "drop_flow",
    "analyze_flow", "export_flow",
    "send_request", "extract_links", "crawl",
}

def test_all_17_tools_registered(tmp_path):
    store = FlowStore(str(tmp_path / "flows.db"))
    addon = FlowStoreAddon(store)
    mcp = create_server(store, addon)
    registered = set(mcp._tool_manager._tools.keys())
    missing = EXPECTED_TOOLS - registered
    assert not missing, f"Missing tools: {missing}"
    store.close()
