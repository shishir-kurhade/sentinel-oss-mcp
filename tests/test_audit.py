from __future__ import annotations

import asyncio
import os
import sqlite3
import stat

import pytest

from sentinel_oss.audit import SQLiteAuditStore
from sentinel_oss.contracts import (
    DecisionStatus,
    EvaluationStage,
    Outcome,
    SafetyDecision,
)


def decision(index: int, outcome: Outcome = Outcome.ALLOW) -> SafetyDecision:
    return SafetyDecision(
        decision_id=f"decision-{index}",
        status=DecisionStatus.COMPLETE,
        outcome=outcome,
        reason_code="TEST",
        message="A safe metadata-only message.",
        policy_id="banking",
        policy_version="1.0.0",
        stage=EvaluationStage.ACTION_POLICY,
        latency_ms=1.25,
    )


@pytest.mark.asyncio
async def test_fresh_store_has_safe_empty_state(tmp_path) -> None:
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    summary = await store.summary()
    assert summary["total_decisions"] == 0
    assert await store.recent() == []


@pytest.mark.asyncio
async def test_store_persists_metadata_only(tmp_path) -> None:
    path = tmp_path / "audit.sqlite3"
    store = SQLiteAuditStore(path)
    await store.record(decision(1, Outcome.BLOCK))

    rows = await store.recent()
    assert len(rows) == 1
    assert rows[0]["outcome"] == "BLOCK"

    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(decisions)").fetchall()}
    forbidden = {"prompt", "content", "draft_output", "arguments", "embedding", "prompt_hash"}
    assert columns.isdisjoint(forbidden)


@pytest.mark.asyncio
async def test_retention_and_concurrent_writes(tmp_path) -> None:
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3", max_records=5)
    await asyncio.gather(*(store.record(decision(index)) for index in range(10)))
    assert (await store.summary())["total_decisions"] == 5
    assert len(await store.recent(limit=100)) == 5


def test_negative_retention_is_rejected(tmp_path) -> None:
    with pytest.raises(ValueError, match="max_records"):
        SQLiteAuditStore(tmp_path / "audit.sqlite3", max_records=-1)


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not available")
async def test_database_files_are_owner_only(tmp_path) -> None:
    path = tmp_path / "private" / "audit.sqlite3"
    store = SQLiteAuditStore(path)

    await store.record(decision(1))

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
