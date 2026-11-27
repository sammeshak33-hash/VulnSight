"""Display model: turn a ``ScanResult`` into plain JSON-compatible data.

This module is pure. It does no I/O, starts no server and never opens a file.
All text is passed through unchanged: it comes from scanned code and is only
ever shown by the page as plain text. Columns are shown 1-based (like the
command-line text report); the JSON export keeps the schema's 0-based columns.
"""

from typing import Any

from vulnsight.cwe import get_cwe
from vulnsight.findings import Finding
from vulnsight.scan_result import IssueLevel, ScanIssue, ScanResult
from vulnsight.scanner.taint_model import TaintLabel

MAX_FINDINGS_SHOWN = 1000


def build_view(
    result: ScanResult,
    *,
    resolved_target: str | None = None,
    max_findings: int = MAX_FINDINGS_SHOWN,
) -> dict[str, Any]:
    """Return the display data for ``result``.

    At most ``max_findings`` findings are included (the first ones, in the
    result's own order). ``findings_total`` always holds the real count and
    ``truncated`` says whether findings were left out. Issues are never cut.
    """

    if not isinstance(result, ScanResult):
        raise ValueError("result must be a ScanResult")

    if isinstance(max_findings, bool) or not isinstance(max_findings, int):
        raise ValueError("max_findings must be an integer")

    if max_findings < 0:
        raise ValueError("max_findings must not be negative")

    shown = result.findings[:max_findings]
    errors = sum(1 for issue in result.issues if issue.level == IssueLevel.ERROR)
    metadata = result.metadata

    return {
        "status": result.status.value,
        "target": result.target,
        "resolved_target": resolved_target,
        "parameter_mode": metadata.settings_dict().get("parameter_mode"),
        "tool_version": metadata.tool_version,
        "files_scanned": metadata.files_scanned,
        "findings_total": len(result.findings),
        "findings_shown": len(shown),
        "truncated": len(shown) < len(result.findings),
        "error_count": errors,
        "warning_count": len(result.issues) - errors,
        "findings": [_finding(finding) for finding in shown],
        "issues": [_issue(issue) for issue in result.issues],
    }


def _finding(finding: Finding) -> dict[str, Any]:
    location = finding.location
    info = get_cwe(finding.cwe)
    sink = finding.sink

    return {
        "id": finding.finding_id,
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "cwe_name": info.name if info is not None else None,
        "confidence": finding.confidence.value,
        "taint_effect": (
            finding.taint_effect.value if finding.taint_effect is not None else None
        ),
        "message": finding.message,
        "file": location.file,
        "line": location.line,
        "column": location.column + 1,
        "end_line": location.end_line,
        "enclosing_function": finding.enclosing_function,
        "sink": (
            None
            if sink is None
            else {"callee": sink.callee, "certainty": sink.certainty.value}
        ),
        "evidence": [_label(label) for label in finding.evidence],
        # Severity and verification are not produced yet. None means "not
        # assessed" (severity) or "not run" (verification); anything present
        # is passed through as the model reports it.
        "severity": (
            finding.severity.to_dict() if finding.severity is not None else None
        ),
        "verification": (
            finding.verification.to_dict() if finding.verification is not None else None
        ),
    }


def _label(label: TaintLabel) -> dict[str, Any]:
    origin = label.origin

    return {
        "origin_id": origin.origin_id,
        "kind": origin.kind.value,
        "line": origin.line,
        "column": origin.col + 1,
        "trace": [
            {
                "kind": step.kind.value,
                "line": step.line,
                "column": step.col + 1,
                "text": step.text,
            }
            for step in label.trace
        ],
        "neutralizations": [
            {"cwe": n.cwe, "platforms": sorted(n.platforms), "via": n.via}
            for n in sorted(
                label.neutralizations, key=lambda n: (n.cwe, n.via, sorted(n.platforms))
            )
        ],
    }


def _issue(issue: ScanIssue) -> dict[str, Any]:
    return {
        "level": issue.level.value,
        "code": issue.code,
        "message": issue.message,
        "file": issue.file,
        "line": issue.line,
    }
