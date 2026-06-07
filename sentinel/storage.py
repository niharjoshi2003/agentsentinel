from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", Path(__file__).resolve().parent.parent / "sentinel.db"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SentinelStore:
    def __init__(self, path: Path | str = DB_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    raw_response TEXT NOT NULL,
                    detector_results_json TEXT NOT NULL,
                    threat_score INTEGER NOT NULL DEFAULT 0,
                    marked_safe INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")

    def log_event(
        self,
        *,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        raw_response: str,
        detector_results: list[dict[str, Any]],
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        timestamp = timestamp or utc_now()
        threat_score = max((int(result.get("score", 0)) for result in detector_results), default=0)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events (
                    timestamp, session_id, tool_name, arguments_json, raw_response,
                    detector_results_json, threat_score
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    session_id,
                    tool_name,
                    json.dumps(arguments, default=str, ensure_ascii=False),
                    raw_response,
                    json.dumps(detector_results, default=str, ensure_ascii=False),
                    threat_score,
                ),
            )
            event_id = cursor.lastrowid
        return self.get_event(int(event_id))

    def get_event(self, event_id: int) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            raise KeyError(f"Event {event_id} not found")
        return self._row_to_event(row)

    def list_events(self, session_id: str, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE session_id = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def recent_responses(self, session_id: str, limit: int = 20) -> list[str]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT raw_response FROM events
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [str(row["raw_response"]) for row in rows]

    def tool_sequence(self, session_id: str, limit: int = 20) -> list[str]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT tool_name FROM events
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [str(row["tool_name"]) for row in reversed(rows)]

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    session_id,
                    COUNT(*) AS total_calls,
                    SUM(CASE WHEN threat_score > 0 AND marked_safe = 0 THEN 1 ELSE 0 END) AS threats_detected,
                    SUM(CASE WHEN threat_score >= 95 AND marked_safe = 0 THEN 1 ELSE 0 END) AS critical_alerts,
                    MAX(threat_score) AS max_threat_score,
                    MAX(timestamp) AS last_seen
                FROM events
                GROUP BY session_id
                ORDER BY last_seen DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def global_stats(self) -> dict[str, Any]:
        sessions = self.list_sessions()
        total_calls = sum(int(session["total_calls"] or 0) for session in sessions)
        threats_detected = sum(int(session["threats_detected"] or 0) for session in sessions)
        critical_alerts = sum(int(session["critical_alerts"] or 0) for session in sessions)
        clean_sessions = sum(1 for session in sessions if int(session["threats_detected"] or 0) == 0)
        clean_sessions_percent = round((clean_sessions / len(sessions)) * 100, 1) if sessions else 100.0
        return {
            "total_calls": total_calls,
            "threats_detected": threats_detected,
            "critical_alerts": critical_alerts,
            "clean_sessions_percent": clean_sessions_percent,
        }

    def mark_safe(self, event_id: int) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE events SET marked_safe = 1, threat_score = 0 WHERE id = ?", (event_id,))
        return self.get_event(event_id)

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "session_id": row["session_id"],
            "tool_name": row["tool_name"],
            "arguments": json.loads(row["arguments_json"]),
            "raw_response": row["raw_response"],
            "detector_results": json.loads(row["detector_results_json"]),
            "threat_score": row["threat_score"],
            "marked_safe": bool(row["marked_safe"]),
        }


store = SentinelStore()
