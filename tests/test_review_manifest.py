from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts.verify_eval_review import verify


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_approved_review_manifest_is_bound_to_corpus_bytes(tmp_path: Path) -> None:
    content = tmp_path / "content.jsonl"
    actions = tmp_path / "actions.jsonl"
    content.write_text('{"id":"content"}\n', encoding="utf-8")
    actions.write_text('{"id":"action"}\n', encoding="utf-8")
    (tmp_path / "review.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "status": "APPROVED",
                "reviewed_by": ["Synthetic Maintainer"],
                "reviewed_at": "2026-08-25T12:00:00Z",
                "content_sha256": _digest(content),
                "actions_sha256": _digest(actions),
            }
        ),
        encoding="utf-8",
    )

    verify(tmp_path)
    content.write_text('{"id":"changed"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="changed after"):
        verify(tmp_path)


def test_bundled_draft_manifest_blocks_release() -> None:
    directory = Path(__file__).parents[1] / "src" / "sentinel_oss" / "eval_data"

    with pytest.raises(ValueError, match="APPROVED"):
        verify(directory)
