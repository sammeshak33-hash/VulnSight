"""Tests for the pure display model of the dashboard."""

import json

import pytest

from tests.finding_builders import make_credential_finding, make_finding, make_label
from vulnsight.engine import ScanEngine
from vulnsight.findings import Location, assign_occurrences
from vulnsight.scan_result import (
    IssueLevel,
    ScanIssue,
    ScanMetadata,
    ScanResult,
    ScanStatus,
)
from vulnsight.scanner.policy import ParameterMode
from vulnsight.scanner.taint_model import Neutralization, TraceKind
from vulnsight.ui.view import MAX_FINDINGS_SHOWN, build_view

HOSTILE = '<img src=x onerror="alert(1)"> & <script>x</script> \' " `'


def scan_files(tmp_path, files, mode=ParameterMode.STRICT):
    for name, text in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    return ScanEngine(parameter_mode=mode).scan_path(str(tmp_path))


def many_findings(tmp_path, count):
    lines = ["import os"] + ["os.system(input())"] * count

    return scan_files(tmp_path, {"big.py": "\n".join(lines) + "\n"})


def test_the_limit_is_one_thousand():
    assert MAX_FINDINGS_SHOWN == 1000


def test_complete_result_summary(tmp_path):
    result = scan_files(
        tmp_path, {"a.py": "import os\nos.system(input())\n", "b.py": "x = 1\n"}
    )
    view = build_view(result, resolved_target="/abs/path")

    assert view["status"] == "complete"
    assert view["target"] == result.target
    assert view["resolved_target"] == "/abs/path"
    assert view["parameter_mode"] == "strict"
    assert view["files_scanned"] == 2
    assert view["findings_total"] == view["findings_shown"] == 1
    assert view["truncated"] is False
    assert (view["error_count"], view["warning_count"]) == (0, 0)
    assert view["issues"] == []


def test_partial_and_failed_results_show_their_issues(tmp_path):
    partial = scan_files(tmp_path, {"ok.py": "x = 1\n", "bad.py": "def (:\n"})
    view = build_view(partial)

    assert view["status"] == "partial"
    assert view["error_count"] == 1
    assert [i["code"] for i in view["issues"]] == ["syntax-error"]
    assert view["issues"][0]["level"] == "error"
    assert view["issues"][0]["file"] == "bad.py"

    failed = build_view(ScanEngine().scan_path(str(tmp_path / "missing")))

    assert failed["status"] == "failed"
    assert failed["files_scanned"] == 0
    assert failed["issues"][0]["code"] == "target-not-found"


def test_warnings_are_counted_separately(tmp_path):
    view = build_view(ScanEngine().scan_path(str(tmp_path)))

    assert view["status"] == "complete"
    assert (view["error_count"], view["warning_count"]) == (0, 1)
    assert view["issues"][0]["code"] == "no-python-files"


def test_recall_mode_is_reported(tmp_path):
    result = scan_files(tmp_path, {"a.py": "x = 1\n"}, ParameterMode.RECALL)

    assert build_view(result)["parameter_mode"] == "recall"


def test_unknown_mode_and_unknown_counts_are_none():
    view = build_view(ScanResult(status=ScanStatus.COMPLETE))

    assert view["parameter_mode"] is None
    assert view["files_scanned"] is None
    assert view["target"] is None
    assert view["resolved_target"] is None


def test_finding_row_and_detail_fields(tmp_path):
    result = scan_files(tmp_path, {"a.py": "import os\nos.system(input())\n"})
    finding = result.findings[0]
    shown = build_view(result)["findings"][0]

    assert shown["id"] == finding.finding_id
    assert shown["rule_id"] == finding.rule_id
    assert shown["cwe"] == "CWE-78"
    assert shown["cwe_name"] == "OS Command Injection"
    assert shown["confidence"] == finding.confidence.value
    assert shown["taint_effect"] == finding.taint_effect.value
    assert shown["message"] == finding.message
    assert shown["file"] == "a.py"
    assert shown["line"] == 2
    assert shown["sink"] == {
        "callee": "os.system",
        "certainty": finding.sink.certainty.value,
    }
    assert shown["enclosing_function"] == finding.enclosing_function
    assert shown["evidence"][0]["origin_id"] == "input()"
    assert shown["evidence"][0]["trace"][0]["kind"] == "source"


def test_columns_are_one_based_in_the_view_and_zero_based_in_the_schema():
    label = make_label(line=4, col=14)
    finding = make_finding(location=Location("a.py", 7, 0), evidence=(label,))
    result = ScanResult(
        status=ScanStatus.COMPLETE, findings=assign_occurrences([finding])
    )
    shown = build_view(result)["findings"][0]

    assert shown["column"] == 1
    assert shown["evidence"][0]["column"] == 15
    assert shown["evidence"][0]["trace"][0]["column"] == 15
    assert shown["evidence"][0]["trace"][1]["column"] == 1
    assert json.loads(result.to_json())["findings"][0]["location"]["column"] == 0


def test_evidence_trace_and_neutralization_details():
    label = make_label(
        steps=(TraceKind.CONCAT, TraceKind.PARTIAL_SANITIZER),
        neutralizations=(
            Neutralization("CWE-78", frozenset({"posix", "windows"}), "q"),
        ),
    )
    result = ScanResult(
        status=ScanStatus.COMPLETE,
        findings=assign_occurrences([make_finding(evidence=(label,))]),
    )
    evidence = build_view(result)["findings"][0]["evidence"][0]

    assert [s["kind"] for s in evidence["trace"]][:2] == ["source", "concat"]
    assert evidence["neutralizations"] == [
        {"cwe": "CWE-78", "platforms": ["posix", "windows"], "via": "q"}
    ]


def test_shortened_trace_keeps_its_order_and_marks_the_gap_as_elided():
    label = make_label(steps=(TraceKind.ASSIGN,) * 20)
    result = ScanResult(
        status=ScanStatus.COMPLETE,
        findings=assign_occurrences([make_finding(evidence=(label,))]),
    )
    trace = build_view(result)["findings"][0]["evidence"][0]["trace"]
    kinds = [step["kind"] for step in trace]

    assert kinds.count("elided") == 1
    assert kinds[0] == "source"
    assert kinds.index("elided") == len(kinds) // 2
    assert kinds[: kinds.index("elided")] == ["source"] + ["assign"] * 5
    assert kinds[kinds.index("elided") + 1 :] == ["assign"] * 5
    assert [s["text"] for s in trace if s["kind"] != "elided"][-1] == "step 20"


def test_every_evidence_origin_is_listed_in_order():
    first = make_label(origin_id="input()", steps=(TraceKind.ASSIGN,))
    second = make_label(origin_id="sys.argv", steps=(TraceKind.CONCAT,))
    result = ScanResult(
        status=ScanStatus.COMPLETE,
        findings=assign_occurrences([make_finding(evidence=(first, second))]),
    )
    evidence = build_view(result)["findings"][0]["evidence"]

    assert [label["origin_id"] for label in evidence] == [
        label.origin.origin_id for label in result.findings[0].evidence
    ]
    assert len(evidence) == 2


def test_finding_without_sink_or_evidence_and_unknown_cwe():
    finding = make_credential_finding(cwe="CWE-99999")
    shown = build_view(
        ScanResult(status=ScanStatus.COMPLETE, findings=assign_occurrences([finding]))
    )["findings"][0]

    assert shown["sink"] is None
    assert shown["evidence"] == []
    assert shown["taint_effect"] is None
    assert shown["cwe"] == "CWE-99999"
    assert shown["cwe_name"] is None


def test_severity_and_verification_are_not_assessed_today(tmp_path):
    result = scan_files(tmp_path, {"a.py": "import os\nos.system(input())\n"})
    shown = build_view(result)["findings"][0]

    assert shown["severity"] is None
    assert shown["verification"] is None


def test_present_severity_is_passed_through_not_invented():
    from tests.finding_builders import make_finding as build
    from vulnsight.findings import SeverityAssessment, SeverityLevel

    severity = SeverityAssessment(SeverityLevel.HIGH, "cvss-test", None, None)
    finding = build(severity=severity)
    shown = build_view(
        ScanResult(status=ScanStatus.COMPLETE, findings=assign_occurrences([finding]))
    )["findings"][0]

    assert shown["severity"] == severity.to_dict()


def test_present_verification_is_passed_through_not_invented():
    from vulnsight.findings import Verification, VerificationVerdict

    verification = Verification(VerificationVerdict.KEPT, 0.75, "model-test")
    finding = make_finding(verification=verification)
    shown = build_view(
        ScanResult(status=ScanStatus.COMPLETE, findings=assign_occurrences([finding]))
    )["findings"][0]

    assert shown["verification"] == verification.to_dict()


def test_at_most_one_thousand_findings_are_shown_and_truncation_is_flagged(tmp_path):
    result = many_findings(tmp_path, 1100)
    view = build_view(result)

    assert len(result.findings) == 1100
    assert view["findings_total"] == 1100
    assert view["findings_shown"] == len(view["findings"]) == 1000
    assert view["truncated"] is True
    assert [f["id"] for f in view["findings"]] == [
        f.finding_id for f in result.findings[:1000]
    ]


def test_exactly_the_limit_is_not_truncated(tmp_path):
    view = build_view(many_findings(tmp_path, 1000))

    assert view["findings_total"] == view["findings_shown"] == 1000
    assert view["truncated"] is False


def test_custom_limits_and_validation(tmp_path):
    result = many_findings(tmp_path, 5)

    assert build_view(result, max_findings=2)["findings_shown"] == 2
    assert build_view(result, max_findings=0)["findings"] == []
    assert build_view(result, max_findings=0)["truncated"] is True

    for bad in (-1, True, 1.5, "3", None):
        with pytest.raises(ValueError, match="max_findings"):
            build_view(result, max_findings=bad)

    with pytest.raises(ValueError, match="ScanResult"):
        build_view({"status": "complete"})


def test_issues_are_never_truncated():
    issues = tuple(
        ScanIssue(IssueLevel.WARNING, "w", f"warning {i}", file=f"f{i}.py", line=1)
        for i in range(1500)
    )
    view = build_view(ScanResult(status=ScanStatus.COMPLETE, issues=issues))

    assert len(view["issues"]) == 1500
    assert view["warning_count"] == 1500


def test_hostile_text_is_passed_through_unchanged_as_plain_data():
    finding = make_finding(
        message=HOSTILE,
        location=Location("<b>x</b>.py", 3, 0),
        enclosing_function="<fn>",
    )
    issue = ScanIssue(IssueLevel.WARNING, "code", HOSTILE, file="<i>.py", line=2)
    result = ScanResult(
        status=ScanStatus.COMPLETE,
        target="<t>",
        findings=assign_occurrences([finding]),
        issues=(issue,),
        metadata=ScanMetadata(),
    )
    view = build_view(result, resolved_target="<abs>")

    assert view["findings"][0]["message"] == HOSTILE
    assert view["findings"][0]["file"] == "<b>x</b>.py"
    assert view["findings"][0]["enclosing_function"] == "<fn>"
    assert view["issues"][0]["message"] == HOSTILE
    assert view["issues"][0]["file"] == "<i>.py"
    assert view["target"] == "<t>"
    assert view["resolved_target"] == "<abs>"


def test_view_is_json_compatible_and_does_not_change_the_result(tmp_path):
    result = scan_files(tmp_path, {"a.py": "import os\nos.system(input())\n"})
    before = result.to_json()
    view = build_view(result)

    assert json.loads(json.dumps(view)) == view
    assert result.to_json() == before


def test_building_the_view_is_deterministic(tmp_path):
    result = many_findings(tmp_path, 30)

    assert build_view(result) == build_view(result)
