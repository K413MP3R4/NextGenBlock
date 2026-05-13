"""
Logger structuré + persistance SQLite des évènements.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from typing import Optional

from ..core.engine import PacketEvent, Verdict


DEFAULT_DB = os.path.join(os.path.expanduser("~"), ".nextgenblock", "logs.db")


class EventLogger:
    """Persiste les évènements (paquet + verdict) dans SQLite."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()
        self._buffer: list[tuple] = []
        self._buffer_size = 50
        self.last_error: Optional[str] = None

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           REAL NOT NULL,
                verdict      TEXT NOT NULL,
                direction    TEXT,
                protocol     TEXT,
                src_addr     TEXT,
                src_port     INTEGER,
                dst_addr     TEXT,
                dst_port     INTEGER,
                src_company  TEXT,
                dst_company  TEXT,
                src_country  TEXT,
                dst_country  TEXT,
                process_name TEXT,
                rule         TEXT,
                tags         TEXT,
                threat_score INTEGER
            )
            """)
            self._ensure_column(conn, "events", "src_company", "TEXT")
            self._ensure_column(conn, "events", "dst_company", "TEXT")
            self._ensure_column(conn, "events", "src_country", "TEXT")
            self._ensure_column(conn, "events", "dst_country", "TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON events(verdict)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dst ON events(dst_addr)")

    def log(self, evt: PacketEvent, verdict: Verdict) -> None:
        row = (
            evt.timestamp, verdict.value, evt.direction, evt.protocol,
            evt.src_addr, evt.src_port, evt.dst_addr, evt.dst_port,
            evt.src_company, evt.dst_company, evt.src_country, evt.dst_country,
            evt.process_name,
            evt.matched_rule, ",".join(evt.tags), evt.threat_score,
        )
        with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= self._buffer_size:
                self._flush()

    def _flush(self) -> None:
        if not self._buffer:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executemany(
                    """INSERT INTO events
                       (ts, verdict, direction, protocol, src_addr, src_port,
                        dst_addr, dst_port, src_company, dst_company,
                        src_country, dst_country, process_name, rule, tags,
                        threat_score)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    self._buffer,
                )
        except sqlite3.Error as e:
            self.last_error = str(e)
            raise RuntimeError(f"SQLite logger write failed: {e}") from e
        else:
            self.last_error = None
            self._buffer.clear()

    def flush(self) -> None:
        with self._lock:
            self._flush()

    def recent(self, limit: int = 200, verdict: Optional[str] = None) -> list[dict]:
        with self._lock:
            self._flush()
        query = "SELECT * FROM events"
        params: list = []
        if verdict:
            query += " WHERE verdict = ?"
            params.append(verdict)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def top_blocked(self, limit: int = 20) -> list[tuple[str, int]]:
        with self._lock:
            self._flush()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT dst_addr, COUNT(*) c FROM events
                   WHERE verdict = 'block'
                   GROUP BY dst_addr ORDER BY c DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return rows

    def counts_by_verdict(self, since: float = 0.0) -> dict[str, int]:
        with self._lock:
            self._flush()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT verdict, COUNT(*) FROM events WHERE ts >= ? GROUP BY verdict",
                (since,),
            ).fetchall()
            return {v: c for v, c in rows}

    def _ensure_column(
        self, conn: sqlite3.Connection, table: str, column: str, definition: str
    ) -> None:
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
