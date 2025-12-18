from __future__ import annotations

from tests.utils.canonicalize import get_deterministic_hash, to_canonical_json


def test_int_and_float_one_hash_identically() -> None:
    """Ensure ``1`` and ``1.0`` canonicalize and hash identically."""

    payload_int = {"val": 1}
    payload_float = {"val": 1.0}

    assert to_canonical_json(payload_int) == to_canonical_json(payload_float)
    assert get_deterministic_hash(payload_int) == get_deterministic_hash(payload_float)


def test_unicode_canonicalization_matches_jcs_example() -> None:
    """Unicode characters should not be ASCII-escaped in canonical JSON."""

    payload = {"text": "ä"}

    # Canonical JCS representation uses the literal UTF-8 character.
    assert to_canonical_json(payload) == '{"text":"ä"}'
