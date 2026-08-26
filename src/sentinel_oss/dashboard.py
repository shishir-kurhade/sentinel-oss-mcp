"""Optional aggregate-only Streamlit dashboard."""

from __future__ import annotations

import asyncio

from sentinel_oss.audit import SQLiteAuditStore


def render() -> None:
    try:
        import streamlit as st
    except ImportError as exc:  # pragma: no cover - optional dependency smoke test
        raise RuntimeError("install sentinel-oss-mcp[dashboard] to run the dashboard") from exc

    store = SQLiteAuditStore()
    summary = asyncio.run(store.summary())

    st.set_page_config(page_title="Sentinel OSS", page_icon="🛡️", layout="wide")
    st.title("Sentinel OSS — Aggregate Decision Metadata")
    st.caption("No prompt, output, tool argument, embedding, or prompt hash is stored.")

    columns = st.columns(4)
    columns[0].metric("Decisions", summary["total_decisions"])
    columns[1].metric("Blocked", summary["blocked_decisions"])
    columns[2].metric("Review", summary["review_decisions"])
    columns[3].metric("Errors", summary["error_decisions"])
    st.metric("Average latency", f"{summary['average_latency_ms']} ms")

    if summary["total_decisions"] == 0:
        st.info("No decisions have been recorded yet.")

    st.caption(f"Last refreshed: {summary['last_updated']}")


if __name__ == "__main__":  # pragma: no cover
    render()
