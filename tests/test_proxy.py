import json
import pytest
from unittest.mock import MagicMock
from cdp_mcp.store import FlowStore
from cdp_mcp.proxy import FlowStoreAddon


@pytest.fixture
def store(tmp_path):
    s = FlowStore(str(tmp_path / "flows.db"))
    yield s
    s.close()


def _make_mock_flow(
    flow_id="flow1",
    host="example.com",
    port=443,
    scheme="https",
    method="GET",
    path="/test",
    query="",
    req_headers=None,
    req_body=b"",
    res_status=200,
    res_headers=None,
    res_body=b"ok",
):
    flow = MagicMock()
    flow.id = flow_id

    flow.request.host = host
    flow.request.port = port
    flow.request.scheme = scheme
    flow.request.method = method
    flow.request.path = path
    flow.request.query_string = query
    flow.request.headers = req_headers or {"Accept": "application/json"}
    flow.request.content = req_body
    flow.request.timestamp_start = 1716000000.0

    flow.response.status_code = res_status
    flow.response.headers = res_headers or {"Content-Type": "text/plain"}
    flow.response.content = res_body
    flow.response.timestamp_end = 1716000000.142

    return flow


def test_response_saves_flow(store):
    addon = FlowStoreAddon(store)
    flow = _make_mock_flow()
    addon.response(flow)
    result = store.get("flow1")
    assert result is not None
    assert result["host"] == "example.com"
    assert result["method"] == "GET"
    assert result["res_status"] == 200


def test_response_calculates_duration(store):
    addon = FlowStoreAddon(store)
    flow = _make_mock_flow()
    flow.request.timestamp_start = 1716000000.0
    flow.response.timestamp_end = 1716000000.5
    addon.response(flow)
    result = store.get("flow1")
    assert result["duration_ms"] == 500


def test_request_intercepts_when_filter_matches(store):
    addon = FlowStoreAddon(store, intercept_filter="example.com")
    flow = _make_mock_flow(host="example.com")
    addon.request(flow)
    flow.intercept.assert_called_once()
    assert "flow1" in addon.intercepted_flows


def test_request_does_not_intercept_when_no_filter(store):
    addon = FlowStoreAddon(store)
    flow = _make_mock_flow()
    addon.request(flow)
    flow.intercept.assert_not_called()


def test_request_does_not_intercept_non_matching_filter(store):
    addon = FlowStoreAddon(store, intercept_filter="other.com")
    flow = _make_mock_flow(host="example.com")
    addon.request(flow)
    flow.intercept.assert_not_called()


def test_set_intercept_filter(store):
    addon = FlowStoreAddon(store)
    addon.set_intercept_filter("api.example.com")
    assert addon.intercept_filter == "api.example.com"


def test_clear_intercept_filter(store):
    addon = FlowStoreAddon(store, intercept_filter="example.com")
    addon.set_intercept_filter(None)
    flow = _make_mock_flow()
    addon.request(flow)
    flow.intercept.assert_not_called()


def test_get_intercepted_flows(store):
    addon = FlowStoreAddon(store, intercept_filter="example.com")
    flow = _make_mock_flow()
    addon.request(flow)
    intercepted = addon.get_intercepted_flows()
    assert len(intercepted) == 1
    assert intercepted[0]["id"] == "flow1"


def test_response_skips_none_response(store):
    addon = FlowStoreAddon(store)
    flow = _make_mock_flow()
    flow.response = None
    addon.response(flow)  # should not raise
    result = store.get("flow1")
    assert result is None  # nothing saved


def test_response_marks_intercepted_flag(store):
    addon = FlowStoreAddon(store, intercept_filter="example.com")
    flow = _make_mock_flow(host="example.com")
    addon.request(flow)  # marks as intercepted
    addon.response(flow)  # saves to DB
    result = store.get("flow1")
    assert result["intercepted"] == 1
