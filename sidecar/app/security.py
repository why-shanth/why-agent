"""Security utilities for scrubbing PII inside the sidecar.

This module implements ``PIIScrubber``, which uses ``presidio-analyzer``
for detection of PII and replaces detected values with a monthly-rotating
SHA-256 hash that includes both:

* An HMAC-based salt derived from the current year and month.
* A secret pepper loaded from the environment.

AI Security note:
- The PII pepper **must** be provided via the ``PII_PEPPER`` environment
  variable. If it is missing or empty, initialization fails (fail-closed).
- The monthly salt secret **must** be provided via the
  ``PII_SALT_SECRET`` environment variable and is also fail-closed.
- Neither secret is ever defaulted to a hardcoded value.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import datetime, timezone
from typing import List, Optional

from presidio_analyzer import AnalyzerEngine, RecognizerResult

__all__ = ["PIIScrubber", "get_salt"]

# Precompiled regexes used as a cheap pre-filter before invoking Presidio.
# This avoids running the heavier NER pipeline on texts that clearly do not
# contain email addresses or phone numbers.
_EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
)

_PHONE_REGEX = re.compile(
    # Very permissive phone pattern covering common international formats.
    r"(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4})"
)


def _load_pepper_from_env() -> str:
    """Load the PII pepper from the environment, failing closed if missing.

    The pepper is treated as a secret and **must** be provided via the
    ``PII_PEPPER`` environment variable. No default or fallback value is
    ever used, to avoid accidentally running in a weakened security mode.
    """

    pepper = os.environ.get("PII_PEPPER")
    if pepper is None or not pepper.strip():
        raise ValueError("Environment variable PII_PEPPER must be set and non-empty")
    return pepper


_DEFAULT_ANALYZER: Optional[AnalyzerEngine] = None
_SALT_SECRET: Optional[bytes] = None


def _get_default_analyzer() -> AnalyzerEngine:
    """Lazily construct and cache the global ``AnalyzerEngine`` instance."""

    global _DEFAULT_ANALYZER
    if _DEFAULT_ANALYZER is None:
        _DEFAULT_ANALYZER = AnalyzerEngine()
    return _DEFAULT_ANALYZER


def _load_salt_secret_from_env() -> bytes:
    """Load the HMAC salt secret from the environment, failing closed if missing."""

    secret = os.environ.get("PII_SALT_SECRET")
    if secret is None or not secret.strip():
        raise ValueError("Environment variable PII_SALT_SECRET must be set and non-empty")
    return secret.encode("utf-8")


def _get_salt_secret() -> bytes:
    """Return the cached salt secret, loading from the environment if needed."""

    global _SALT_SECRET
    if _SALT_SECRET is None:
        _SALT_SECRET = _load_salt_secret_from_env()
    return _SALT_SECRET


def get_salt(timestamp: datetime) -> str:
    """Derive a monthly-rotating salt using HMAC(SECRET, year-month).

    The ``SECRET`` is loaded from the ``PII_SALT_SECRET`` environment
    variable and cached in memory. The timestamp is normalized to an
    ``YYYY-MM`` string in UTC before HMAC derivation.
    """

    # Normalize to year-month in UTC for rotation.
    year_month = timestamp.astimezone(timezone.utc).strftime("%Y-%m")
    secret = _get_salt_secret()
    digest = hmac.new(secret, msg=year_month.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()
    return digest


class PIIScrubber:
    """Scrub PII from free-form text using peppered hashing.

    This class detects PII using ``presidio-analyzer`` and replaces any
    detected email addresses or phone numbers with a deterministic hash
    of the form::

        SHA256(entity_text + monthly_salt + PII_PEPPER)

    where ``monthly_salt`` is derived from the current UTC year and month,
    and ``PII_PEPPER`` is a secret value loaded from the environment.
    """

    # Entities we care about for scrubbing.
    ENTITIES = ("EMAIL_ADDRESS", "PHONE_NUMBER")

    def __init__(self, analyzer: Optional[AnalyzerEngine] = None) -> None:
        # Fail-closed if the pepper or salt secret is not configured correctly.
        self._pepper: str = _load_pepper_from_env()
        # Touch the salt secret at construction time so misconfiguration
        # is detected eagerly rather than on first scrub call.
        _get_salt_secret()
        # Reuse a shared AnalyzerEngine instance by default to avoid
        # the overhead of repeatedly constructing recognizers.
        self._analyzer: AnalyzerEngine = analyzer or _get_default_analyzer()

    def scrub(self, text: str) -> str:
        """Return ``text`` with email addresses and phone numbers hashed.

        Detected entities are replaced with a hexadecimal SHA-256 digest of
        ``entity_text + monthly_salt + PII_PEPPER``. If no PII is found,
        the original text is returned unchanged.
        """

        if not text:
            return text

        # Fast-path: if the lightweight regexes find no candidate patterns,
        # avoid invoking the heavier Presidio analyzer entirely.
        if not (_EMAIL_REGEX.search(text) or _PHONE_REGEX.search(text)):
            return text

        results: List[RecognizerResult] = self._analyzer.analyze(
            text=text,
            entities=list(self.ENTITIES),
            language="en",
        )

        if not results:
            return text

        # Sort by start index so we can rebuild the string efficiently.
        results = sorted(results, key=lambda r: (r.start or 0, r.end or 0))

        scrubbed_parts: list[str] = []
        cursor = 0

        for res in results:
            # Some recognizers can, in theory, return None indices; skip them.
            if res.start is None or res.end is None:
                continue

            # Skip overlapping entities to avoid double-replacement and
            # potential index errors.
            if res.start < cursor:
                continue

            # Keep the non-PII segment as-is.
            scrubbed_parts.append(text[cursor : res.start])

            # Hash the detected PII span.
            entity_text = text[res.start : res.end]
            scrubbed_parts.append(self._hash_entity(entity_text))

            cursor = res.end

        # Append any trailing non-PII text.
        scrubbed_parts.append(text[cursor:])

        return "".join(scrubbed_parts)

    def _hash_entity(self, value: str) -> str:
        """Hash a single PII value using SHA-256 with HMAC-based monthly salt + pepper."""

        # Monthly salt is derived via HMAC(PII_SALT_SECRET, YYYY-MM), which
        # allows correlating the same PII within a month while naturally
        # rotating identifiers over time.
        monthly_salt = get_salt(datetime.now(timezone.utc))

        material = f"{value}{monthly_salt}{self._pepper}".encode("utf-8")
        digest = hashlib.sha256(material).hexdigest()
        return digest
