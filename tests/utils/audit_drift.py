from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

from whylogs.core.view.dataset_profile_view import DatasetProfileView

try:  # pragma: no cover - import paths differ across whylogs versions
    from whylogs.viz.drift.column_drift_algorithms import calculate_drift_scores
    from whylogs.viz.drift.configs import DriftConfig
except ImportError:  # pragma: no cover
    # Older whylogs releases exposed these directly from whylogs.viz.drift.
    from whylogs.viz.drift import calculate_drift_scores, DriftConfig  # type: ignore[assignment]


DEFAULT_THRESHOLD = 0.15


def _load_profile_view(path: Path) -> DatasetProfileView:
    """Load a serialized whylogs DatasetProfileView from ``path``."""

    return DatasetProfileView.read(str(path))


def _compute_max_hellinger_distance(
    baseline: DatasetProfileView,
    candidate: DatasetProfileView,
    threshold: float,
) -> float:
    """Return the maximum Hellinger distance observed across all columns."""

    drift_config = DriftConfig(algorithm="hellinger", threshold=threshold)

    scores = calculate_drift_scores(
        target_view=candidate,
        reference_view=baseline,
        config=drift_config,
        with_thresholds=True,
    )

    max_distance = 0.0

    # ``scores`` is typically a mapping of column name -> ColumnDriftMetric
    # (or a dict-like payload) depending on the whylogs version. We extract
    # the numeric drift distance in a version-tolerant way.
    for _column, info in scores.items():  # type: ignore[assignment]
        distance: float | None = None

        # Object-style attributes first.
        for attr in ("distance", "drift_score", "metric"):
            if hasattr(info, attr):
                value = getattr(info, attr)
                if isinstance(value, (int, float)):
                    distance = float(value)
                    break

        # Dict-style payloads.
        if distance is None and isinstance(info, Dict):
            for key in ("distance", "drift_score", "metric"):
                value = info.get(key)
                if isinstance(value, (int, float)):
                    distance = float(value)
                    break

        if distance is None:
            continue

        if distance > max_distance:
            max_distance = distance

    return max_distance


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for CI/CD drift audit reports.

    This tool compares a candidate profile against a baseline profile
    using whylogs' Hellinger distance implementation. If the maximum
    per-column Hellinger distance exceeds the configured threshold
    (default: 0.15), the process exits with code 1 so that a PR check
    can fail hard on significant data drift.
    """

    parser = argparse.ArgumentParser(
        description="Compute Hellinger drift between whylogs profiles and enforce a hard threshold.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Path to baseline DatasetProfileView file (whylogs serialized view).",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        required=True,
        help="Path to candidate DatasetProfileView file (whylogs serialized view).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="Maximum allowed Hellinger distance before failing the check.",
    )

    args = parser.parse_args(argv)

    baseline_view = _load_profile_view(args.baseline)
    candidate_view = _load_profile_view(args.candidate)

    max_distance = _compute_max_hellinger_distance(
        baseline=baseline_view,
        candidate=candidate_view,
        threshold=args.threshold,
    )

    if max_distance > args.threshold:
        print(
            f"Hellinger drift check FAILED: max distance {max_distance:.4f} "
            f"exceeds threshold {args.threshold:.4f}",
        )
        return 1

    print(
        f"Hellinger drift check passed: max distance {max_distance:.4f} "
        f"(threshold {args.threshold:.4f})",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

