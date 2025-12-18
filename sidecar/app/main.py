"""FastAPI-based Guardrail API for the why-agent sidecar.

This module exposes a minimal HTTP API that evaluates incoming
prompts for security risks (prompt injection and toxicity) using
LangKit metrics, and logs anonymized telemetry to whylogs.

Key behaviors:
- PII is scrubbed from prompts via ``PIIScrubber`` before any logging.
- LangKit's LLM metrics schema is initialized on application startup.
- Logging to whylogs happens asynchronously via FastAPI ``BackgroundTasks``
  so that telemetry export does not add latency to the main request path.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

import logging
import os

import whylogs as why
from fastapi import BackgroundTasks, FastAPI, Request
from langkit import llm_metrics
from opentelemetry import metrics, trace
from opentelemetry.exporter.prometheus import PrometheusMetricsExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export.controller import PushController
from pydantic import BaseModel
from prometheus_client import start_http_server

from .security import PIIScrubber


app = FastAPI(title="Why Agent Guardrail Sidecar")

logger = logging.getLogger("why_agent.sidecar")

# Global LangKit/whylogs schema, initialized on startup.
_LLM_SCHEMA = None

# Single shared PIIScrubber instance (constructed on startup).
_PIISCRUBBER: PIIScrubber | None = None

# OpenTelemetry metrics instruments, initialized on startup.
_METRICS_INITIALIZED = False
_TOXICITY_HISTOGRAM = None
_BLOCKED_COUNTER = None


class AnalysisRequest(BaseModel):
    """Request body for the /analyze endpoint."""

    prompt: str


def _get_llm_schema():
    """Return the global LangKit LLM metrics schema, initializing if needed."""

    global _LLM_SCHEMA
    if _LLM_SCHEMA is None:
        _LLM_SCHEMA = llm_metrics.init()
    return _LLM_SCHEMA


def _init_observability() -> None:
    """Initialize OpenTelemetry instrumentation and Prometheus metrics.

    This sets up:
    - OTel instrumentation for FastAPI and logging.
    - A PrometheusMetricsExporter publishing metrics on a dedicated port.
    - Meter + instruments for toxicity histogram and blocked request counter.
    """

    global _METRICS_INITIALIZED, _TOXICITY_HISTOGRAM, _BLOCKED_COUNTER

    if _METRICS_INITIALIZED:
        return

    # Instrument FastAPI for OpenTelemetry traces.
    FastAPIInstrumentor.instrument_app(app)

    # Ensure Python logging records OTel trace/context fields.
    LoggingInstrumentor().instrument(set_logging_format=True)

    # Configure Prometheus exporter and meter.
    metrics.set_meter_provider(MeterProvider())
    meter = metrics.get_meter(__name__)

    exporter = PrometheusMetricsExporter()

    # Publish metrics for Prometheus scraping on a separate HTTP port
    # to avoid interfering with the main FastAPI service port.
    metrics_host = os.environ.get("METRICS_HOST", "0.0.0.0")
    metrics_port = int(os.environ.get("METRICS_PORT", "9464"))
    start_http_server(port=metrics_port, addr=metrics_host)

    # PushController will periodically collect metrics and expose them
    # via the Prometheus exporter.
    PushController(meter, exporter, 5)

    _TOXICITY_HISTOGRAM = meter.create_histogram(
        name="sidecar_toxicity_score",
        description="Toxicity scores for prompts evaluated by the sidecar.",
        unit="1",
    )
    _BLOCKED_COUNTER = meter.create_counter(
        name="sidecar_blocked_count",
        description="Total number of blocked prompts.",
        unit="1",
    )

    _METRICS_INITIALIZED = True


def _extract_trace_id_from_headers(request: Request) -> str | None:
    """Best-effort extraction of an upstream trace ID from HTTP headers.

    Priority order:
    1. W3C ``traceparent`` header.
    2. Common trace headers (``x-trace-id``, ``x-request-id``, ``x-b3-traceid``).
    3. Current OpenTelemetry span context, if any.
    """

    traceparent = request.headers.get("traceparent")
    if traceparent:
        parts = traceparent.split("-")
        if len(parts) >= 2 and parts[1]:
            return parts[1]

    for header_name in ("x-trace-id", "x-request-id", "x-b3-traceid"):
        header_value = request.headers.get(header_name)
        if header_value:
            return header_value

    # Fallback: derive from the current OpenTelemetry span, if present.
    span = trace.get_current_span()
    span_ctx = span.get_span_context() if span is not None else None
    if span_ctx is not None and span_ctx.trace_id:
        return format(span_ctx.trace_id, "032x")

    return None


@app.middleware("http")
async def _logging_context_middleware(request: Request, call_next):
    """Attach an upstream trace ID (if any) to the logger context.

    This enables correlation between the sidecar's logs and the main
    application's distributed traces.
    """

    trace_id = _extract_trace_id_from_headers(request)
    request.state.trace_id = trace_id

    if trace_id:
        request.state.logger = logging.LoggerAdapter(logger, {"trace_id": trace_id})
    else:
        request.state.logger = logger

    response = await call_next(request)
    return response


@app.on_event("startup")
def _init_startup() -> None:
    """Initialize LangKit metrics and the PII scrubber on application startup."""

    global _PIISCRUBBER
    _get_llm_schema()
    # Constructing PIIScrubber here will fail-closed if PII_PEPPER is not set.
    _PIISCRUBBER = PIIScrubber()
    _init_observability()


def _extract_first_numeric(mapping: Dict[Any, Any]) -> float | None:
    """Return the first numeric value from a nested mapping, if any.

    This helper is intentionally defensive because the exact pandas
    layout produced by ``profile_view.to_pandas()`` can vary between
    whylogs versions. We simply scan for the first int/float value.
    """

    for value in mapping.values():
        if isinstance(value, (int, float)):
            return float(value)
    return None


def _find_metric_value(df: Any, candidate_keys: Tuple[str, ...]) -> float:
    """Best-effort lookup of a LangKit metric value in a pandas DataFrame.

    The structure produced by ``DatasetProfileView.to_pandas()`` is not
    guaranteed to be stable across versions, so this helper performs a
    tolerant search across both columns and indices and falls back to
    ``0.0`` when the metric cannot be located.
    """

    try:
        data = df.to_dict()  # type: ignore[no-untyped-call]
    except Exception:
        return 0.0

    # ``data`` is typically {column_name: {index_name: value, ...}, ...}
    for key in candidate_keys:
        # Direct column match.
        if key in data:
            col_mapping = data[key]
            if isinstance(col_mapping, dict):
                numeric = _extract_first_numeric(col_mapping)
                if numeric is not None:
                    return numeric

        # Search within each column's index mapping.
        for col_mapping in data.values():
            if isinstance(col_mapping, dict) and key in col_mapping:
                value = col_mapping[key]
                if isinstance(value, (int, float)):
                    return float(value)

    return 0.0


def _compute_langkit_scores(scrubbed_prompt: str) -> Tuple[float, float]:
    """Compute prompt injection and toxicity scores for a scrubbed prompt.

    This function uses whylogs + LangKit's LLM metrics schema to
    analyze a single prompt and returns a pair of floats in the
    range [0.0, 1.0]: ``(injection_score, toxicity_score)``.

    If LangKit metrics cannot be resolved (for example, due to version
    mismatches), this function gracefully falls back to ``0.0`` for
    both scores.
    """

    schema = _get_llm_schema()

    # Use LangKit's LLM metrics via whylogs profiling.
    try:
        results = why.log({"prompt": scrubbed_prompt}, schema=schema)
    except Exception:
        return 0.0, 0.0

    profile_view = None
    # Support both modern and older whylogs return types.
    if hasattr(results, "view"):
        profile_view = results.view()
    elif hasattr(results, "profile"):
        profile = results.profile()  # type: ignore[no-untyped-call]
        if hasattr(profile, "view"):
            profile_view = profile.view()

    if profile_view is None or not hasattr(profile_view, "to_pandas"):
        return 0.0, 0.0

    try:
        df = profile_view.to_pandas()
    except Exception:
        return 0.0, 0.0

    # Metric names may vary slightly depending on configuration; try the
    # most common ones used by LangKit for guardrail-style checks.
    injection_score = _find_metric_value(
        df,
        (
            "prompt.injection",
            "prompt.similarity.injection",
        ),
    )

    toxicity_score = _find_metric_value(
        df,
        (
            "toxicity",
            "prompt.toxicity.toxicity_score",
            "response.toxicity.toxicity_score",
        ),
    )

    return float(injection_score), float(toxicity_score)


def _log_to_whylogs(scrubbed_prompt: str, injection_score: float, toxicity_score: float) -> None:
    """Background task that logs the scrubbed prompt and scores to whylogs.

    This function is designed to run off the main request thread via
    ``BackgroundTasks`` so that telemetry export never blocks user
    responses.
    """

    payload = {
        "prompt": scrubbed_prompt,
        "prompt.injection": float(injection_score),
        "toxicity": float(toxicity_score),
    }

    try:
        why.log(payload, schema=_get_llm_schema())
    except Exception:
        # Logging failures must never break the main application path.
        return


@app.post("/analyze")
async def analyze(
    analysis_request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> Dict[str, Any]:
    """Analyze a prompt for security risks.

    Steps:
    A. Scrub PII from the incoming prompt.
    B. Calculate prompt injection and toxicity scores using LangKit.
    C. If either score exceeds 0.8, block the request.
    D. Asynchronously log the scrubbed prompt and scores to whylogs.
    """

    if _PIISCRUBBER is None:
        # Failsafe: if startup initialization did not run for some reason,
        # construct a scrubber on-demand. This will still respect the
        # fail-closed behavior of ``PIIScrubber``.
        scrubber = PIIScrubber()
    else:
        scrubber = _PIISCRUBBER

    # Step A: Scrub PII from the prompt.
    scrubbed_prompt = scrubber.scrub(analysis_request.prompt)

    # Step B: Use LangKit metrics to compute scores.
    injection_score, toxicity_score = _compute_langkit_scores(scrubbed_prompt)

    # Step C: Apply guardrail decision.
    threshold = 0.8
    if injection_score > threshold or toxicity_score > threshold:
        allowed = False
        reason = "Security Risk"
    else:
        allowed = True
        reason = "Allowed"

    # Record observability metrics. Metrics collection must never block or
    # fail the main request path, so all errors are swallowed.
    if _TOXICITY_HISTOGRAM is not None:
        try:
            _TOXICITY_HISTOGRAM.record(float(toxicity_score))
        except Exception:
            pass

    if not allowed and _BLOCKED_COUNTER is not None:
        try:
            _BLOCKED_COUNTER.add(1)
        except Exception:
            pass

    # Application-level structured log including upstream trace correlation.
    req_logger = getattr(request.state, "logger", logger)
    log_extra: Dict[str, Any] = {
        "allowed": allowed,
        "reason": reason,
        "injection_score": injection_score,
        "toxicity": toxicity_score,
    }
    trace_id_value = getattr(request.state, "trace_id", None)
    if trace_id_value:
        log_extra["trace_id"] = trace_id_value

    try:
        req_logger.info("sidecar.analyze.completed", extra=log_extra)
    except Exception:
        # Logging failures must never affect the user-visible response.
        pass

    # Step D: Log asynchronously to whylogs to avoid adding latency.
    background_tasks.add_task(
        _log_to_whylogs,
        scrubbed_prompt,
        injection_score,
        toxicity_score,
    )

    return {
        "allowed": allowed,
        "reason": reason,
        "injection_score": injection_score,
        "toxicity": toxicity_score,
    }
