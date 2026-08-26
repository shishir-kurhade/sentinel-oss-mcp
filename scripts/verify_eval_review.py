"""Fail a release unless human review is recorded for the exact evaluation corpus."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def verify(directory: Path) -> None:
    manifest_path = directory / "review.json"
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "1" or manifest.get("status") != "APPROVED":
        raise ValueError("the evaluation corpus does not have APPROVED human-review status")
    reviewers = manifest.get("reviewed_by")
    if (
        not isinstance(reviewers, list)
        or not reviewers
        or not all(isinstance(item, str) and item.strip() for item in reviewers)
    ):
        raise ValueError("reviewed_by must identify at least one human maintainer")
    reviewed_at = manifest.get("reviewed_at")
    if not isinstance(reviewed_at, str):
        raise ValueError("reviewed_at must be an ISO-8601 timestamp")
    datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))

    for name in ("content", "actions"):
        expected = manifest.get(f"{name}_sha256")
        actual = hashlib.sha256((directory / f"{name}.jsonl").read_bytes()).hexdigest()
        if expected != actual:
            raise ValueError(f"{name}.jsonl changed after the recorded human review")


def main() -> int:
    directory = Path(__file__).parents[1] / "src" / "sentinel_oss" / "eval_data"
    try:
        verify(directory)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Evaluation review gate failed: {exc}")
        return 1
    print("Evaluation corpus review manifest is approved and hash-bound.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
