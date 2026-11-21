"""Builders shared by the Finding v2 and ScanResult tests."""

from vulnsight.findings import (
    ConfidenceLevel,
    Finding,
    Language,
    Location,
    SeverityAssessment,
    SeverityLevel,
    Sink,
    Verification,
    VerificationVerdict,
    assign_occurrences,
)
from vulnsight.scan_result import (
    IssueLevel,
    ScanIssue,
    ScanMetadata,
    ScanResult,
    ScanStatus,
)
from vulnsight.scanner.scope import ResolutionCertainty
from vulnsight.scanner.taint_model import (
    Neutralization,
    SourceKind,
    TaintEffect,
    TaintLabel,
    TaintOrigin,
    TraceKind,
    TraceStep,
)


def make_label(
    origin_id="input()",
    kind=SourceKind.INTERACTIVE,
    line=10,
    col=14,
    steps=(TraceKind.ASSIGN,),
    neutralizations=(),
):
    """Build a TaintLabel whose trace is SOURCE followed by ``steps``."""

    trace = [TraceStep(TraceKind.SOURCE, line, col, origin_id)]

    for offset, step_kind in enumerate(steps, start=1):
        trace.append(TraceStep(step_kind, line + offset, 0, f"step {offset}"))

    return TaintLabel(
        origin=TaintOrigin(origin_id, kind, line, col),
        trace=tuple(trace),
        neutralizations=frozenset(neutralizations),
    )


def make_finding(**overrides):
    """Build a valid taint finding. Keyword arguments replace fields."""

    fields = {
        "rule_id": "PY-CMD-001",
        "cwe": "CWE-78",
        "language": Language.PYTHON,
        "message": "Potential command injection",
        "location": Location("app/run.py", 12, 4, 12, 30),
        "confidence": ConfidenceLevel.MEDIUM,
        "enclosing_function": "execute",
        "sink": Sink("os.system", ResolutionCertainty.DEFINITE),
        "evidence": (make_label(),),
        "taint_effect": TaintEffect.RAW,
    }
    fields.update(overrides)

    return Finding(**fields)


def make_credential_finding(**overrides):
    """Build a non-taint finding: no sink and no evidence."""

    fields = {
        "rule_id": "PY-SECRET-001",
        "cwe": "CWE-798",
        "message": "Hard-coded credential",
        "location": Location("app/config.py", 3, 0, 3, 28),
        "confidence": ConfidenceLevel.LOW,
        "enclosing_function": "<module>",
        "sink": None,
        "evidence": (),
        "taint_effect": None,
    }
    fields.update(overrides)

    return make_finding(**fields)


def golden_scan_result():
    """A fixed, fully populated result used by the golden-file tests."""

    sanitized = make_label(
        origin_id="sys.argv",
        kind=SourceKind.CLI_ARG,
        line=4,
        col=8,
        steps=(TraceKind.CONCAT, TraceKind.PARTIAL_SANITIZER),
        neutralizations=(
            Neutralization("CWE-78", frozenset({"posix"}), "shlex.quote"),
        ),
    )

    findings = assign_occurrences(
        [
            make_finding(),
            make_finding(
                location=Location("app/run.py", 20, 4, 20, 31),
                message="Potential command injection (café)",
                evidence=(sanitized,),
                taint_effect=TaintEffect.PARTIAL,
                structure_hash="0123456789abcdef0123456789abcdef",
            ),
            make_credential_finding(),
            make_finding(
                rule_id="C-BUF-001",
                cwe="CWE-120",
                language=Language.C,
                message="Unbounded copy into fixed buffer",
                location=Location("native/copy.c", 7, 4),
                enclosing_function="copy_name",
                sink=Sink("strcpy", ResolutionCertainty.POSSIBLE),
                evidence=(),
                taint_effect=None,
                severity=SeverityAssessment(
                    level=SeverityLevel.HIGH,
                    method="example",
                    score=8.1,
                    vector=None,
                    assumptions=("local attacker",),
                ),
                verification=Verification(
                    VerificationVerdict.KEPT, 0.75, "example-model"
                ),
            ),
        ]
    )

    return ScanResult(
        status=ScanStatus.COMPLETE,
        target="src",
        findings=findings,
        issues=(
            ScanIssue(
                IssueLevel.WARNING,
                "skipped-file",
                "Binary file skipped",
                file="assets\\logo.png",
            ),
        ),
        metadata=ScanMetadata.with_settings(
            {"parameter_mode": "strict"},
            files_scanned=3,
            tool_version="0.1.0",
            created_at="2026-01-01T00:00:00Z",
        ),
    )


__all__ = [
    "golden_scan_result",
    "make_credential_finding",
    "make_finding",
    "make_label",
]
