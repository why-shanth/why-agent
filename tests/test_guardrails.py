"""Golden-sample regression tests for the sidecar guardrail API.

These tests load a set of canonical examples from ``tests/data/golden.json``
and ensure that the sidecar's ``/analyze`` verdicts remain stable over time.

If the underlying behavior changes intentionally, the golden set in
``golden.json`` must be updated alongside the code change; otherwise,
these tests will fail and prevent silent behavioral drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from tests.utils.canonicalize import get_deterministic_hash


_GOLDEN_PATH = Path(__file__).parent / "data" / "golden.json"


def _load_golden_samples() -> List[Dict[str, Any]]:
    with _GOLDEN_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("sample", _load_golden_samples())
def test_guardrail_golden_samples(sample: Dict[str, Any], test_client: TestClient) -> None:
    """Ensure the sidecar's allowed verdict matches the golden expectation.

    For each sample we:

    * Send the ``input`` text to the real ``/analyze`` endpoint of the
      sidecar (running in-memory via ``TestClient``).
    * Assert that the ``allowed`` field matches ``expected_verdict``.
    * Compute a deterministic hash of the full JSON response and
      compare it against ``expected_hash``; this catches any structured
      behavior drift beyond the single boolean flag.
    """

    response = test_client.post("/analyze", json={"prompt": sample["input"]})
    assert response.status_code == 200

    payload = response.json()

    # Primary regression assertion: allowed verdict must match.
    assert payload["allowed"] is sample["expected_verdict"], (
        f"Golden sample '{sample.get('id')}' changed: expected "
        f"allowed={sample['expected_verdict']}, got {payload['allowed']}"
    )

    # Secondary regression assertion: entire response structure should
    # remain stable unless the golden file is explicitly updated.
    actual_hash = get_deterministic_hash(payload)
    assert (
        actual_hash == sample["expected_hash"]
    ), (
        f"Golden sample '{sample.get('id')}' response hash drifted. "
        f"Expected {sample['expected_hash']}, got {actual_hash}. "
        "If this change is intentional, update tests/data/golden.json."
    )
