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
