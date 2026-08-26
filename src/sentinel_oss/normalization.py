"""Deterministic text normalization used before every content decision."""

from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
_WHITESPACE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Normalize compatibility characters and remove common invisible separators."""

    normalized = unicodedata.normalize("NFKC", text)
    normalized = _ZERO_WIDTH.sub("", normalized)
    normalized = _WHITESPACE.sub(" ", normalized)
    return normalized.strip()
