"""Metadata-only local audit storage.

This module deliberately accepts only SafetyDecision objects. Request content and tool
arguments cannot accidentally enter the persistence boundary.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sentinel_oss.contracts import SafetyDecision


def default_data_dir() -> Path:
    override = os.getenv("SENTINEL_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "SentinelOSS"
    if os.name == "nt":
        root = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "SentinelOSS"
    root = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "sentinel-oss"


class AuditSink(Protocol):
    async def record(self, decision: SafetyDecision) -> None: ...

    async def summary(self) -> dict[str, int | float | str]: ...

    async def recent(self, limit: int = 50) -> list[dict[str, object]]: ...


class NullAuditStore:
    async def record(self, decision: SafetyDecision) -> None:
        del decision

    async def summary(self) -> dict[str, int | float | str]:
        return _empty_summary()

    async def recent(self, limit: int = 50) -> list[dict[str, object]]:
        del limit
        return []


class SQLiteAuditStore:
    def __init__(self, path: str | Path | None = None, *, max_records: int = 10_000) -> None:
        if max_records < 0:
            raise ValueError("max_records must not be negative")
        self.path = Path(path) if path is not None else default_data_dir() / "audit.sqlite3"
        self.max_records = max_records
        self._lock = threading.Lock()
        self._initialized = False

    async def record(self, decision: SafetyDecision) -> None:
        await asyncio.to_thread(self._record_sync, decision)

    async def summary(self) -> dict[str, int | float | str]:
        return await asyncio.to_thread(self._summary_sync)

    async def recent(self, limit: int = 50) -> list[dict[str, object]]:
        bounded = max(1, min(limit, 500))
        return await asyncio.to_thread(self._recent_sync, bounded)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        self._secure_database_files()
        return connection

    def _secure_database_files(self) -> None:
        if os.name == "nt":
            return
        for candidate in (
            self.path,
            self.path.with_name(f"{self.path.name}-wal"),
            self.path.with_name(f"{self.path.name}-shm"),
        ):
            try:
                candidate.chmod(0o600)
            except FileNotFoundError:
                continue

    def _ensure_initialized(self, connection: sqlite3.Connection) -> None:
        if self._initialized:
            return
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                decision_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                outcome TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                stage TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                provider_id TEXT,
                provider_model TEXT,
                latency_ms REAL NOT NULL,
                requires_confirmation INTEGER NOT NULL,
                matched_rule_ids TEXT NOT NULL
            )
            """
        )
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(decisions)").fetchall()
        }
        if "provider_id" not in columns:
            connection.execute("ALTER TABLE decisions ADD COLUMN provider_id TEXT")
        connection.commit()
        self._initialized = True

    def _record_sync(self, decision: SafetyDecision) -> None:
        with self._lock, self._connect() as connection:
            self._ensure_initialized(connection)
            connection.execute(
                """
                INSERT OR REPLACE INTO decisions (
                    recorded_at, decision_id, status, outcome, reason_code, stage,
                    policy_id, policy_version, provider_id, provider_model, latency_ms,
                    requires_confirmation, matched_rule_ids
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(UTC).isoformat(),
                    decision.decision_id,
                    decision.status.value,
                    decision.outcome.value,
                    decision.reason_code,
                    decision.stage.value,
                    decision.policy_id,
                    decision.policy_version,
                    decision.provider_id,
                    decision.model_id,
                    decision.latency_ms,
                    int(decision.requires_confirmation),
                    json.dumps(decision.matched_rule_ids),
                ),
            )
            if self.max_records > 0:
                connection.execute(
                    """
                    DELETE FROM decisions
                    WHERE sequence NOT IN (
                        SELECT sequence FROM decisions ORDER BY sequence DESC LIMIT ?
                    )
                    """,
                    (self.max_records,),
                )
            connection.commit()

    def _summary_sync(self) -> dict[str, int | float | str]:
        with self._lock, self._connect() as connection:
            self._ensure_initialized(connection)
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN outcome = 'BLOCK' THEN 1 ELSE 0 END) AS blocked,
                       SUM(CASE WHEN outcome = 'REVIEW' THEN 1 ELSE 0 END) AS reviewed,
                       SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) AS errors,
                       AVG(latency_ms) AS average_latency
                FROM decisions
                """
            ).fetchone()
        if row is None or row["total"] == 0:
            return _empty_summary()
        return {
            "total_decisions": int(row["total"]),
            "blocked_decisions": int(row["blocked"] or 0),
            "review_decisions": int(row["reviewed"] or 0),
            "error_decisions": int(row["errors"] or 0),
            "average_latency_ms": round(float(row["average_latency"] or 0.0), 2),
            "last_updated": datetime.now(UTC).isoformat(),
        }

    def _recent_sync(self, limit: int) -> list[dict[str, object]]:
        with self._lock, self._connect() as connection:
            self._ensure_initialized(connection)
            rows = connection.execute(
                """
                SELECT recorded_at, decision_id, status, outcome, reason_code, stage,
                       policy_id, policy_version, provider_id, provider_model, latency_ms,
                       requires_confirmation, matched_rule_ids
                FROM decisions ORDER BY sequence DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_safe_row(row) for row in rows]


def _safe_row(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "recorded_at": row["recorded_at"],
        "decision_id": row["decision_id"],
        "status": row["status"],
        "outcome": row["outcome"],
        "reason_code": row["reason_code"],
        "stage": row["stage"],
        "policy_id": row["policy_id"],
        "policy_version": row["policy_version"],
        "provider_id": row["provider_id"],
        "provider_model": row["provider_model"],
        "latency_ms": row["latency_ms"],
        "requires_confirmation": bool(row["requires_confirmation"]),
        "matched_rule_ids": json.loads(str(row["matched_rule_ids"])),
    }


def _empty_summary() -> dict[str, int | float | str]:
    return {
        "total_decisions": 0,
        "blocked_decisions": 0,
        "review_decisions": 0,
        "error_decisions": 0,
        "average_latency_ms": 0.0,
        "last_updated": datetime.now(UTC).isoformat(),
    }


__all__ = ["AuditSink", "NullAuditStore", "SQLiteAuditStore", "default_data_dir"]
