import json
import pytest
import tempfile
import os
from cdp_mcp.store import FlowStore

@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "flows.db")
    s = FlowStore(db_path)
    yield s
    s.close()

def _sample_flow(flow_id="abc123"):
    return {
        "id": flow_id,
        "timestamp": 1716000000.0,
        "host": "example.com",
        "port": 443,
        "scheme": "https",
        "method": "POST",
        "path": "/api/login",
        "query": "ref=home",
        "req_headers": json.dumps({"Content-Type": "application/json"}),
        "req_body": b'{"user":"admin","pass":"secret"}',
        "res_status": 200,
        "res_headers": json.dumps({"Content-Type": "application/json"}),
        "res_body": b'{"token":"eyJhbGciOiJIUzI1NiJ9.x.y"}',
        "duration_ms": 142,
        "intercepted": 0,
        "replayed": 0,
        "tags": json.dumps([]),
    }

def test_insert_and_get(store):
    flow = _sample_flow()
    store.insert(flow)
    result = store.get("abc123")
    assert result["host"] == "example.com"
    assert result["method"] == "POST"

def test_list_all(store):
    store.insert(_sample_flow("id1"))
    store.insert(_sample_flow("id2"))
    results = store.list_flows()
    assert len(results) == 2

def test_list_filter_host(store):
    store.insert(_sample_flow("id1"))
    f2 = _sample_flow("id2")
    f2["host"] = "other.com"
    store.insert(f2)
    results = store.list_flows(host="example.com")
    assert len(results) == 1
    assert results[0]["id"] == "id1"

def test_list_filter_method(store):
    store.insert(_sample_flow("id1"))
    f2 = _sample_flow("id2")
    f2["method"] = "GET"
    store.insert(f2)
    results = store.list_flows(method="GET")
    assert len(results) == 1

def test_list_filter_status(store):
    store.insert(_sample_flow("id1"))
    f2 = _sample_flow("id2")
    f2["res_status"] = 404
    store.insert(f2)
    results = store.list_flows(status_code=404)
    assert len(results) == 1

def test_list_limit(store):
    for i in range(5):
        store.insert(_sample_flow(f"id{i}"))
    results = store.list_flows(limit=3)
    assert len(results) == 3

def test_search_in_path(store):
    store.insert(_sample_flow("id1"))
    results = store.search("login")
    assert len(results) == 1

def test_search_in_body(store):
    store.insert(_sample_flow("id1"))
    results = store.search("admin")
    assert len(results) == 1

def test_search_no_match(store):
    store.insert(_sample_flow("id1"))
    results = store.search("zzznomatch")
    assert len(results) == 0

def test_get_not_found(store):
    result = store.get("nonexistent")
    assert result is None

def test_update_replayed(store):
    store.insert(_sample_flow("id1"))
    store.update("id1", replayed=1)
    result = store.get("id1")
    assert result["replayed"] == 1

def test_count(store):
    store.insert(_sample_flow("id1"))
    store.insert(_sample_flow("id2"))
    assert store.count() == 2
