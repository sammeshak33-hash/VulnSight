"""Evaluation foundation: benchmark models and finding-level metrics (M2.1)."""

from vulnsight.eval.benchmark import (
    BENCHMARK_SCHEMA_VERSION,
    Benchmark,
    BenchmarkCase,
    ExpectedFinding,
)
from vulnsight.eval.metrics import (
    LINE_TOLERANCE,
    CaseResult,
    Counts,
    EvaluationResult,
    Match,
    evaluate,
    evaluate_case,
    is_compatible,
)

__all__ = [
    "BENCHMARK_SCHEMA_VERSION",
    "LINE_TOLERANCE",
    "Benchmark",
    "BenchmarkCase",
    "CaseResult",
    "Counts",
    "EvaluationResult",
    "ExpectedFinding",
    "Match",
    "evaluate",
    "evaluate_case",
    "is_compatible",
]
