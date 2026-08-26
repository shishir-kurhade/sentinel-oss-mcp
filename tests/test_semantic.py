from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

from sentinel_oss.providers import ProviderError, ScriptedEmbedder
from sentinel_oss.semantic import (
    DEFAULT_REVIEWED_PATTERNS,
    LanceSemanticRouter,
    NullSemanticRouter,
    SemanticMatch,
)


class FakeQuery:
    def __init__(self, results: list[dict[str, object]]) -> None:
        self.results = results
        self.metric_name: str | None = None
        self.result_limit: int | None = None

    def metric(self, name: str) -> FakeQuery:
        self.metric_name = name
        return self

    def limit(self, value: int) -> FakeQuery:
        self.result_limit = value
        return self

    def to_list(self) -> list[dict[str, object]]:
        return self.results


class FakeTable:
    def __init__(self, results: list[dict[str, object]]) -> None:
        self.results = results
        self.search_vectors: list[list[float]] = []
        self.queries: list[FakeQuery] = []

    def search(self, vector: list[float]) -> FakeQuery:
        self.search_vectors.append(vector)
        query = FakeQuery(self.results)
        self.queries.append(query)
        return query


class FakeDatabase:
    def __init__(
        self,
        *,
        existing: bool = False,
        results: list[dict[str, object]] | None = None,
    ) -> None:
        self.names = ["reviewed_patterns_v1"] if existing else []
        self.results = results or []
        self.table_names_calls = 0
        self.created: list[tuple[str, list[dict[str, object]], str]] = []
        self.table = FakeTable(self.results)

    def table_names(self) -> list[str]:
        self.table_names_calls += 1
        return list(self.names)

    def create_table(self, name: str, records: list[dict[str, object]], *, mode: str) -> FakeTable:
        self.created.append((name, records, mode))
        self.names.append(name)
        return self.table

    def open_table(self, name: str) -> FakeTable:
        assert name == "reviewed_patterns_v1"
        return self.table


def install_fake_lancedb(monkeypatch: pytest.MonkeyPatch, database: FakeDatabase) -> list[Path]:
    connected: list[Path] = []
    module = ModuleType("lancedb")

    def connect(path: Path) -> FakeDatabase:
        connected.append(path)
        return database

    module.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "lancedb", module)
    return connected


@pytest.mark.asyncio
async def test_null_router_is_deterministic_and_dependency_free() -> None:
    assert await NullSemanticRouter().score("anything") == SemanticMatch(score=0.0)


@pytest.mark.asyncio
async def test_lance_router_initializes_only_reviewed_patterns_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = FakeDatabase(results=[{"_distance": 0.2, "pattern_id": "reviewed-one"}])
    connected = install_fake_lancedb(monkeypatch, database)
    vectors = {
        pattern.text: [float(index), 0.0]
        for index, pattern in enumerate(DEFAULT_REVIEWED_PATTERNS, start=1)
    }
    vectors.update({"first query": [0.1, 0.2], "second query": [0.3, 0.4]})
    embedder = ScriptedEmbedder(vectors=vectors, default=[0.0, 0.0])
    router = LanceSemanticRouter(db_path=tmp_path / "vectors", embedder=embedder)

    first = await router.score("first query")
    second = await router.score("second query")

    assert connected == [tmp_path / "vectors"]
    assert first == second == SemanticMatch(score=0.8, pattern_id="reviewed-one")
    assert database.table_names_calls == 1
    assert len(database.created) == 1
    table_name, records, mode = database.created[0]
    assert table_name == "reviewed_patterns_v1"
    assert mode == "create"
    assert records == [
        {
            "vector": vectors[pattern.text],
            "pattern_id": pattern.pattern_id,
            "text": pattern.text,
        }
        for pattern in DEFAULT_REVIEWED_PATTERNS
    ]
    assert embedder.calls == [
        *(pattern.text for pattern in DEFAULT_REVIEWED_PATTERNS),
        "first query",
        "second query",
    ]
    assert database.table.search_vectors == [[0.1, 0.2], [0.3, 0.4]]
    assert all(query.metric_name == "cosine" for query in database.table.queries)
    assert all(query.result_limit == 1 for query in database.table.queries)


@pytest.mark.asyncio
async def test_existing_table_skips_pattern_embedding_and_empty_search_is_safe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = FakeDatabase(existing=True, results=[])
    install_fake_lancedb(monkeypatch, database)
    embedder = ScriptedEmbedder(vectors={"query": [1.0]}, default=[0.0])
    router = LanceSemanticRouter(db_path=tmp_path, embedder=embedder)

    assert await router.score("query") == SemanticMatch(score=0.0)
    assert database.created == []
    assert embedder.calls == ["query"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("distance", "expected"),
    [(-0.25, 1.0), (0.4, 0.6), (1.25, 0.0)],
)
async def test_similarity_score_is_clamped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    distance: float,
    expected: float,
) -> None:
    database = FakeDatabase(
        existing=True,
        results=[{"_distance": distance, "pattern_id": "pattern"}],
    )
    install_fake_lancedb(monkeypatch, database)
    router = LanceSemanticRouter(
        db_path=tmp_path,
        embedder=ScriptedEmbedder(vectors={}, default=[1.0]),
    )

    result = await router.score("query")

    assert result.score == pytest.approx(expected)
    assert result.pattern_id == "pattern"


def test_lance_router_reports_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(sys.modules, "lancedb", None)

    with pytest.raises(ProviderError, match=r"sentinel-oss-mcp\[vector\]"):
        LanceSemanticRouter(
            db_path=tmp_path,
            embedder=ScriptedEmbedder(vectors={}, default=[0.0]),
        )
