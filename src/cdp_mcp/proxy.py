import json
import threading
from typing import Optional
from urllib.parse import urlsplit
from cdp_mcp.store import FlowStore


class FlowStoreAddon:
    def __init__(self, store: FlowStore, intercept_filter: Optional[str] = None):
        self.store = store
        self.intercept_filter = intercept_filter
        self.intercepted_flows: dict = {}
        self._lock = threading.Lock()

    def set_intercept_filter(self, filter_str: Optional[str]) -> None:
        self.intercept_filter = filter_str

    def request(self, flow) -> None:
        if self.intercept_filter and self.intercept_filter in flow.request.host:
            flow.intercept()
            with self._lock:
                self.intercepted_flows[flow.id] = flow

    def response(self, flow) -> None:
        if flow.response is None:
            return
        duration_ms = int(
            (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
        )
        with self._lock:
            was_intercepted = flow.id in self.intercepted_flows
        record = {
            "id": flow.id,
            "timestamp": flow.request.timestamp_start,
            "host": flow.request.host,
            "port": flow.request.port,
            "scheme": flow.request.scheme,
            "method": flow.request.method,
            "path": flow.request.path,
            "query": urlsplit(flow.request.url).query,
            "req_headers": json.dumps(dict(flow.request.headers)),
            "req_body": flow.request.content,
            "res_status": flow.response.status_code,
            "res_headers": json.dumps(dict(flow.response.headers)),
            "res_body": flow.response.content,
            "duration_ms": duration_ms,
            "intercepted": 1 if was_intercepted else 0,
            "replayed": 0,
            "tags": json.dumps([]),
        }
        self.store.insert(record)

    def get_intercepted_flows(self) -> list[dict]:
        with self._lock:
            snapshot = list(self.intercepted_flows.items())
        return [
            {
                "id": flow_id,
                "host": flow.request.host,
                "method": flow.request.method,
                "path": flow.request.path,
                "scheme": flow.request.scheme,
            }
            for flow_id, flow in snapshot
        ]
