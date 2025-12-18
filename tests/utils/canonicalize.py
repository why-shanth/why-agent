"""Deterministic canonicalization helpers for golden-sample testing.

This module exposes :func:`get_deterministic_hash`, which produces a
stable SHA-256 hash for an arbitrary JSON-like payload by:

* Recursively sorting all dictionary keys.
* Normalizing string values by replacing UUIDs and ISO-8601 dates with
  placeholders (``<UUID>`` and ``<DATE>``).
* Serializing to JSON with compact separators.

The goal is to ensure that semantically equivalent payloads that differ
only in dictionary key order or ephemeral identifiers yield the same hash.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict

__all__ = ["get_deterministic_hash", "to_canonical_json"]

# RFC 4122-style UUID (versions 1–5). Case-insensitive.
_UUID_REGEX = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-"
    r"[0-9a-fA-F]{12}\b"
)

# Rough ISO-8601 date / datetime matcher, covering:
# - YYYY-MM-DD
# - YYYY-MM-DDTHH:MM:SS
# - YYYY-MM-DDTHH:MM:SS.sssZ
# - YYYY-MM-DDTHH:MM:SS±HH:MM
_ISO_DATE_REGEX = re.compile(
    r"\b"  # word boundary
    r"\d{4}-\d{2}-\d{2}"  # date
    r"(?:"  # optional time + timezone
    r"[T ]\d{2}:\d{2}:\d{2}"  # time
    r"(?:\.\d+)?"  # optional fractional seconds
    r"(?:Z|[+-]\d{2}:\d{2})?"  # optional timezone
    r")?"
    r"\b",
)


def _normalize_string(value: str) -> str:
    """Normalize dynamic substrings (UUIDs, dates) inside a string.

    This makes hashes robust to IDs and timestamps while preserving the
    rest of the string content for comparison.
    """

    value = _UUID_REGEX.sub("<UUID>", value)
    value = _ISO_DATE_REGEX.sub("<DATE>", value)
    return value


def _normalize(value: Any) -> Any:
    """Recursively normalize a JSON-like structure.

    - ``dict``: keys are sorted, values normalized.
    - ``list`` / ``tuple``: elements normalized in order.
    - ``str``: UUIDs and ISO dates are replaced with placeholders.
    - Other JSON scalars are returned as-is.
    """

    if isinstance(value, dict):
        # Sort keys to make dictionary order deterministic.
        return {key: _normalize(value[key]) for key in sorted(value.keys())}

    if isinstance(value, list):
        return [_normalize(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_normalize(item) for item in value)

    if isinstance(value, str):
        return _normalize_string(value)

    # RFC 8785-style numeric normalization:
    # - Floats that represent whole numbers are canonicalized to ``int`` so
    #   that ``1`` and ``1.0`` serialize identically.
    if isinstance(value, float):
        if value.is_integer():
            # Treat both 1.0 and -0.0 as the integer 0, etc.
            return int(value)
        return value

    # For any other type (int, bool, None, etc.), return as-is.
    return value


def to_canonical_json(payload: Dict[str, Any]) -> str:
    """Return the canonical JSON string representation for ``payload``.

    This mirrors the JSON Canonicalization Scheme (RFC 8785) for the
    subset of features we rely on in tests:
    - Deterministic key ordering.
    - Stable Unicode handling (no ASCII-escaping of non-ASCII characters).
    - Normalized numeric representation for integral floats.
    """

    normalized = _normalize(payload)

    return json.dumps(
        normalized,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )


def get_deterministic_hash(payload: Dict[str, Any]) -> str:
    """Return a deterministic SHA-256 hex digest for ``payload``.

    The payload is first normalized (sorted dict keys, UUID/date
    canonicalization) and then serialized to JSON with compact separators
    and sorted keys before hashing.
    """

    canonical_json = to_canonical_json(payload)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
