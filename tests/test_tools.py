import json
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from cdp_mcp.server import create_server, ProxyState


@pytest.fixture
def store():
    m = MagicMock()
    m.count.return_value = 5
    return m


@pytest.fixture
def addon():
    return MagicMock()


@pytest.fixture
def proxy_state():
    return ProxyState()


# --- Proxy management ---

def test_get_proxy_status_stopped(store, addon, proxy_state):
    proxy_state.running = False
    result = proxy_state.status(store)
    assert result["running"] is False
    assert result["flow_count"] == 0


def test_get_proxy_status_running(store, addon, proxy_state):
    proxy_state.running = True
    proxy_state.port = 8080
    result = proxy_state.status(store)
    assert result["running"] is True
    assert result["port"] == 8080
    assert result["flow_count"] == 5


def test_start_proxy_already_running(store, addon, proxy_state):
    proxy_state.running = True
    result = proxy_state.start(store, addon, port=8080)
    assert "already running" in result["error"]


def test_stop_proxy_not_running(store, addon, proxy_state):
    proxy_state.running = False
    result = proxy_state.stop()
    assert "not running" in result["error"]


# --- Flow exploration helpers ---

def _flow_record(flow_id="f1", host="example.com", method="GET",
                 path="/api", res_status=200, req_body=b"", res_body=b"ok",
                 req_headers=None, res_headers=None, query=""):
    return {
        "id": flow_id,
        "timestamp": 1716000000.0,
        "host": host,
        "port": 443,
        "scheme": "https",
        "method": method,
        "path": path,
        "query": query,
        "req_headers": json.dumps(req_headers or {}),
        "req_body": req_body,
        "res_status": res_status,
        "res_headers": json.dumps(res_headers or {}),
        "res_body": res_body,
        "duration_ms": 100,
        "intercepted": 0,
        "replayed": 0,
        "tags": json.dumps([]),
    }


def _get_tool(mcp, name):
    """Helper to get a tool function by name from FastMCP."""
    return mcp._tool_manager._tools[name].fn


def test_list_flows_calls_store(store, addon):
    store.list_flows.return_value = [_flow_record()]
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "list_flows")(host="example.com", limit=10)
    store.list_flows.assert_called_once_with(
        host="example.com", path=None, method=None, status_code=None, limit=10
    )
    assert len(result) == 1


def test_get_flow_returns_detail(store, addon):
    record = _flow_record(res_body=b'{"key":"val"}')
    store.get.return_value = record
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "get_flow")("f1")
    assert result["id"] == "f1"
    assert result["res_body"] == '{"key":"val"}'


def test_get_flow_not_found(store, addon):
    store.get.return_value = None
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "get_flow")("missing")
    assert "error" in result


def test_search_flows_calls_store(store, addon):
    store.search.return_value = [_flow_record()]
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "search_flows")("admin")
    store.search.assert_called_once_with("admin")
    assert len(result) == 1


def test_decode_body_returns_string_for_text(store, addon):
    record = _flow_record(res_body=b"hello world")
    store.get.return_value = record
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "get_flow")("f1")
    assert result["res_body"] == "hello world"


def test_decode_body_returns_base64_for_binary(store, addon):
    import base64
    binary = bytes(range(256))
    record = _flow_record(res_body=binary)
    store.get.return_value = record
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "get_flow")("f1")
    # binary content should be base64-encoded string
    decoded = base64.b64decode(result["res_body"])
    assert decoded == binary


# --- Replay and fuzzing ---

def test_replay_flow_not_found(store, addon):
    store.get.return_value = None
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "replay_flow")("missing")
    assert "error" in result


@patch("cdp_mcp.server.http_requests.request")
def test_replay_flow_sends_request(mock_req, store, addon):
    record = _flow_record(
        method="POST", path="/api/login",
        req_headers={"Content-Type": "application/json"},
        req_body=b'{"user":"admin"}',
    )
    store.get.return_value = record
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.content = b'{"ok":true}'
    mock_req.return_value = mock_resp

    mcp = create_server(store, addon)
    result = _get_tool(mcp, "replay_flow")("f1")
    mock_req.assert_called_once()
    assert result["status_code"] == 200


@patch("cdp_mcp.server.http_requests.request")
def test_replay_flow_with_header_modification(mock_req, store, addon):
    record = _flow_record(req_headers={"Authorization": "Bearer old"})
    store.get.return_value = record
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.headers = {}
    mock_resp.content = b"unauthorized"
    mock_req.return_value = mock_resp

    mcp = create_server(store, addon)
    result = _get_tool(mcp, "replay_flow")("f1", modifications={"headers": {"Authorization": "Bearer new"}})
    call_kwargs = mock_req.call_args[1]
    assert call_kwargs["headers"]["Authorization"] == "Bearer new"


@patch("cdp_mcp.server.http_requests.request")
def test_fuzz_flow_repeats_n_times(mock_req, store, addon):
    record = _flow_record(path="/api/item", query="id=1")
    store.get.return_value = record
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.content = b"ok"
    mock_req.return_value = mock_resp

    mcp = create_server(store, addon)
    result = _get_tool(mcp, "fuzz_flow")("f1", field="query.id", values=["1", "2", "3"])
    assert len(result) == 3
    assert mock_req.call_count == 3


def test_fuzz_flow_not_found(store, addon):
    store.get.return_value = None
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "fuzz_flow")("missing", field="query.id", values=["1", "2"])
    assert len(result) == 1
    assert "error" in result[0]


# --- Active interception ---

def test_enable_intercept_sets_filter(store, addon):
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "enable_intercept")(filter="api.example.com")
    addon.set_intercept_filter.assert_called_once_with("api.example.com")
    assert result["intercept_enabled"] is True


def test_enable_intercept_no_filter(store, addon):
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "enable_intercept")()
    addon.set_intercept_filter.assert_called_once_with(None)
    assert result["intercept_enabled"] is True


def test_get_intercepted_returns_list(store, addon):
    addon.get_intercepted_flows.return_value = [
        {"id": "f1", "host": "api.example.com", "method": "POST", "path": "/login", "scheme": "https"}
    ]
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "get_intercepted")()
    assert len(result) == 1
    assert result[0]["id"] == "f1"


def test_release_flow_not_in_intercepted(store, addon):
    addon.intercepted_flows = {}
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "release_flow")("missing")
    assert "error" in result


def test_drop_flow_not_in_intercepted(store, addon):
    addon.intercepted_flows = {}
    mcp = create_server(store, addon)
    result = _get_tool(mcp, "drop_flow")("missing")
    assert "error" in result


def test_release_flow_resumes(store, addon):
    mock_flow = MagicMock()
    mock_flow.request.host = "example.com"
    mock_flow.request.method = "GET"
    mock_flow.request.path = "/test"
    mock_flow.request.scheme = "https"
    mock_flow.request.port = 443
    mock_flow.request.query_string = ""
    mock_flow.request.headers = {}
    mock_flow.request.content = b""
    addon.intercepted_flows = {"f1": mock_flow}
    addon._loop = None

    mcp = create_server(store, addon)
    with patch("cdp_mcp.server._schedule_resume") as mock_resume:
        result = _get_tool(mcp, "release_flow")("f1")
    mock_resume.assert_called_once()
    assert result["released"] is True
    assert "f1" not in addon.intercepted_flows


def test_drop_flow_kills(store, addon):
    mock_flow = MagicMock()
    addon.intercepted_flows = {"f1": mock_flow}
    addon._loop = None

    mcp = create_server(store, addon)
    with patch("cdp_mcp.server._schedule_drop") as mock_drop:
        result = _get_tool(mcp, "drop_flow")("f1")
    mock_drop.assert_called_once()
    assert result["dropped"] is True
    assert "f1" not in addon.intercepted_flows
