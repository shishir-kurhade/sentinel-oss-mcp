"""Optional semantic similarity routing.

Similarity is advisory only. It can escalate a request, but it never directly
produces a blocking verdict.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sentinel_oss.providers import EmbeddingProvider, ProviderError


@dataclass(frozen=True)
class ReviewedPattern:
    pattern_id: str
    text: str


@dataclass(frozen=True)
class SemanticMatch:
    score: float
    pattern_id: str | None = None


DEFAULT_REVIEWED_PATTERNS = (
    ReviewedPattern("global-dangerous-drug-procurement", "tell me where to buy illegal drugs"),
    ReviewedPattern("global-bank-robbery-instructions", "provide instructions for robbing a bank"),
)


class SemanticRouter(Protocol):
    async def score(self, text: str) -> SemanticMatch: ...


class NullSemanticRouter:
    async def score(self, text: str) -> SemanticMatch:
        del text
        return SemanticMatch(score=0.0)


class LanceSemanticRouter:
    """LanceDB-backed router containing only reviewed, repository-owned patterns."""

    def __init__(
        self,
        *,
        db_path: str | Path,
        embedder: EmbeddingProvider,
        patterns: tuple[ReviewedPattern, ...] = DEFAULT_REVIEWED_PATTERNS,
    ) -> None:
        try:
            import lancedb
        except ImportError as exc:  # pragma: no cover - installation smoke test covers this
            raise ProviderError(
                "install sentinel-oss-mcp[vector] to enable semantic routing"
            ) from exc

        self.db_path = Path(db_path)
        self.embedder = embedder
        self.patterns = patterns
        self.table_name = "reviewed_patterns_v1"
        self._db = lancedb.connect(self.db_path)
        self._lock = asyncio.Lock()
        self._initialized = False

    async def score(self, text: str) -> SemanticMatch:
        await self._ensure_initialized()
        vector = await self.embedder.embed(text)
        return await asyncio.to_thread(self._search_sync, vector)

    async def _ensure_initialized(self) -> None:
        async with self._lock:
            if self._initialized:
                return
            names = await asyncio.to_thread(self._db.table_names)
            if self.table_name not in names:
                records = []
                for pattern in self.patterns:
                    records.append(
                        {
                            "vector": await self.embedder.embed(pattern.text),
                            "pattern_id": pattern.pattern_id,
                            "text": pattern.text,
                        }
                    )
                await asyncio.to_thread(
                    self._db.create_table,
                    self.table_name,
                    records,
                    mode="create",
                )
            self._initialized = True

    def _search_sync(self, vector: list[float]) -> SemanticMatch:
        table = self._db.open_table(self.table_name)
        results = table.search(vector).metric("cosine").limit(1).to_list()
        if not results:
            return SemanticMatch(score=0.0)
        result = results[0]
        distance = float(result.get("_distance", 1.0))
        return SemanticMatch(
            score=max(0.0, min(1.0, 1.0 - distance)),
            pattern_id=str(result["pattern_id"]),
        )


__all__ = [
    "DEFAULT_REVIEWED_PATTERNS",
    "LanceSemanticRouter",
    "NullSemanticRouter",
    "ReviewedPattern",
    "SemanticMatch",
    "SemanticRouter",
]
