"""Pytest configuration and fixtures for the sidecar golden tests.

These tests must be fully deterministic and offline:

* We prevent real LangKit / LLM work by monkeypatching the LangKit
  integration helpers in ``sidecar.app.main``.
* We set a dummy ``PII_PEPPER`` so that ``PIIScrubber`` can be
  constructed without leaking any real secret.
"""

from __future__ import annotations

import os
from typing import Callable, Tuple

import pytest
from fastapi.testclient import TestClient

from sidecar.app import main as sidecar_main


@pytest.fixture(scope="session")
def test_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Return a FastAPI TestClient wired to the sidecar app.

    The fixture:

    * Sets a non-secret test pepper so ``PIIScrubber`` can initialize.
    * Monkeypatches LangKit-related helpers so no real LLM or external
      services are used during tests.
    * Returns a ``TestClient`` that exercises the real FastAPI routing
      and guardrail logic.
    """

    # Ensure PIIScrubber can be constructed (fail-closed by default if unset).
    monkeypatch.setenv("PII_PEPPER", "test-pepper")
    monkeypatch.setenv("PII_SALT_SECRET", "test-salt-secret")

    # Make Prometheus metrics export safe and isolated during tests.
    monkeypatch.setenv("METRICS_HOST", "127.0.0.1")
    monkeypatch.setenv("METRICS_PORT", "9464")

    # Stub out LangKit schema initialization so no real metrics schema
    # or heavy dependencies are pulled in during tests.
    def _fake_get_llm_schema() -> object:
        # The concrete value is never used because we also stub the
        # score computation below; it only needs to be non-None.
        return object()

    monkeypatch.setattr(sidecar_main, "_get_llm_schema", _fake_get_llm_schema)

    # Deterministic scoring stub: we consider prompts containing certain
    # keywords as risky, everything else as benign. This keeps tests
    # stable while still exercising the guardrail decision logic.
    def _fake_compute_langkit_scores(scrubbed_prompt: str) -> Tuple[float, float]:
        text = scrubbed_prompt.lower()
        if "exfiltrate" in text or "password" in text:
            # Clearly risky / prompt injection-like prompt.
            return 0.9, 0.0
        if "toxic" in text or "hate" in text:
            # Clearly toxic content.
            return 0.0, 0.9
        # Otherwise treat as safe.
        return 0.1, 0.1

    monkeypatch.setattr(
        sidecar_main,
        "_compute_langkit_scores",
        _fake_compute_langkit_scores,
    )

    # Construct a TestClient that will run startup/shutdown events using
    # the patched helpers above.
    with TestClient(sidecar_main.app) as client:
        yield client
