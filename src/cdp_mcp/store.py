import sqlite3
import threading
from typing import Optional


CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS flows (
    id          TEXT PRIMARY KEY,
    timestamp   REAL,
    host        TEXT,
    port        INTEGER,
    scheme      TEXT,
    method      TEXT,
    path        TEXT,
    query       TEXT,
    req_headers TEXT,
    req_body    BLOB,
    res_status  INTEGER,
    res_headers TEXT,
    res_body    BLOB,
    duration_ms INTEGER,
    intercepted INTEGER DEFAULT 0,
    replayed    INTEGER DEFAULT 0,
    tags        TEXT DEFAULT '[]'
)
"""


class FlowStore:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(CREATE_TABLE)
        self._conn.commit()

    def insert(self, flow: dict) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO flows VALUES (
                    :id, :timestamp, :host, :port, :scheme, :method, :path,
                    :query, :req_headers, :req_body, :res_status, :res_headers,
                    :res_body, :duration_ms, :intercepted, :replayed, :tags
                )""",
                flow,
            )
            self._conn.commit()

    def get(self, flow_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM flows WHERE id = ?", (flow_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_flows(
        self,
        host: str = None,
        path: str = None,
        method: str = None,
        status_code: int = None,
        limit: int = 100,
    ) -> list[dict]:
        clauses, params = [], []
        if host:
            clauses.append("host = ?")
            params.append(host)
        if path:
            clauses.append("path LIKE ?")
            params.append(f"%{path}%")
        if method:
            clauses.append("method = ?")
            params.append(method.upper())
        if status_code is not None:
            clauses.append("res_status = ?")
            params.append(status_code)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM flows {where} ORDER BY timestamp DESC LIMIT ?", params
        ).fetchall()
        return [dict(r) for r in rows]

    def search(self, query: str) -> list[dict]:
        like = f"%{query}%"
        rows = self._conn.execute(
            """SELECT * FROM flows WHERE
               host LIKE ? OR path LIKE ? OR query LIKE ?
               OR CAST(req_body AS TEXT) LIKE ?
               OR CAST(res_body AS TEXT) LIKE ?
               OR req_headers LIKE ? OR res_headers LIKE ?
               ORDER BY timestamp DESC LIMIT 100""",
            (like, like, like, like, like, like, like),
        ).fetchall()
        return [dict(r) for r in rows]

    def update(self, flow_id: str, **kwargs) -> None:
        allowed = {"replayed", "intercepted", "tags"}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        with self._lock:
            self._conn.execute(
                f"UPDATE flows SET {set_clause} WHERE id = ?",
                (*fields.values(), flow_id),
            )
            self._conn.commit()

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
