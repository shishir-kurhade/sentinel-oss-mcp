from __future__ import annotations

import sys
from types import ModuleType

import pytest

from sentinel_oss import dashboard


class FakeColumn:
    def __init__(self) -> None:
        self.metrics: list[tuple[str, object]] = []

    def metric(self, label: str, value: object) -> None:
        self.metrics.append((label, value))


class FakeStreamlit(ModuleType):
    def __init__(self) -> None:
        super().__init__("streamlit")
        self.page_config: dict[str, object] | None = None
        self.titles: list[str] = []
        self.captions: list[str] = []
        self.columns_created = [FakeColumn() for _ in range(4)]
        self.metrics: list[tuple[str, object]] = []
        self.subheaders: list[str] = []
        self.dataframes: list[tuple[object, dict[str, object]]] = []
        self.infos: list[str] = []

    def set_page_config(self, **kwargs: object) -> None:
        self.page_config = kwargs

    def title(self, value: str) -> None:
        self.titles.append(value)

    def caption(self, value: str) -> None:
        self.captions.append(value)

    def columns(self, count: int) -> list[FakeColumn]:
        assert count == 4
        return self.columns_created

    def metric(self, label: str, value: object) -> None:
        self.metrics.append((label, value))

    def subheader(self, value: str) -> None:
        self.subheaders.append(value)

    def dataframe(self, value: object, **kwargs: object) -> None:
        self.dataframes.append((value, kwargs))

    def info(self, value: str) -> None:
        self.infos.append(value)


class FakeStore:
    def __init__(self, *, total: int) -> None:
        self.total = total
        self.recent_limits: list[int] = []

    async def summary(self) -> dict[str, int | float | str]:
        return {
            "total_decisions": self.total,
            "blocked_decisions": int(self.total > 0),
            "review_decisions": int(self.total > 1),
            "error_decisions": int(self.total > 2),
            "average_latency_ms": 2.5 if self.total else 0.0,
            "last_updated": "2026-08-25T00:00:00+00:00",
        }

    async def recent(self, limit: int = 50) -> list[dict[str, object]]:
        self.recent_limits.append(limit)
        raise AssertionError("the aggregate-only dashboard must not read individual rows")


def install_optional_modules(monkeypatch: pytest.MonkeyPatch) -> FakeStreamlit:
    streamlit = FakeStreamlit()
    monkeypatch.setitem(sys.modules, "streamlit", streamlit)
    return streamlit


def test_dashboard_renders_aggregate_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamlit = install_optional_modules(monkeypatch)
    store = FakeStore(total=3)
    monkeypatch.setattr(dashboard, "SQLiteAuditStore", lambda: store)

    dashboard.render()

    assert streamlit.page_config == {
        "page_title": "Sentinel OSS",
        "page_icon": "🛡️",
        "layout": "wide",
    }
    assert streamlit.titles == ["Sentinel OSS — Aggregate Decision Metadata"]
    assert "No prompt, output, tool argument" in streamlit.captions[0]
    assert [column.metrics for column in streamlit.columns_created] == [
        [("Decisions", 3)],
        [("Blocked", 1)],
        [("Review", 1)],
        [("Errors", 1)],
    ]
    assert streamlit.metrics == [("Average latency", "2.5 ms")]
    assert store.recent_limits == []
    assert streamlit.dataframes == []
    assert streamlit.infos == []
    assert streamlit.captions[-1] == "Last refreshed: 2026-08-25T00:00:00+00:00"


def test_dashboard_handles_fresh_empty_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamlit = install_optional_modules(monkeypatch)
    store = FakeStore(total=0)
    monkeypatch.setattr(dashboard, "SQLiteAuditStore", lambda: store)

    dashboard.render()

    assert streamlit.dataframes == []
    assert streamlit.infos == ["No decisions have been recorded yet."]


def test_dashboard_reports_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_optional_modules(monkeypatch)
    monkeypatch.setitem(sys.modules, "streamlit", None)

    with pytest.raises(RuntimeError, match=r"sentinel-oss-mcp\[dashboard\]"):
        dashboard.render()
