import dataclasses
import itertools

import pytest
from finding_builders import make_credential_finding, make_finding

from vulnsight.findings import Location, assign_occurrences
from vulnsight.scan_result import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    IssueLevel,
    ScanIssue,
    ScanMetadata,
    ScanResult,
    ScanStatus,
)


def error_issue(**overrides):
    fields = {
        "level": IssueLevel.ERROR,
        "code": "syntax-error",
        "message": "Invalid Python source",
        "file": "bad.py",
        "line": 3,
    }
    fields.update(overrides)

    return ScanIssue(**fields)


def warning_issue(**overrides):
    return error_issue(
        level=IssueLevel.WARNING,
        code="skipped",
        message="File skipped",
        **overrides,
    )


# ---------------------------------------------------------------
# Construction
# ---------------------------------------------------------------


def test_empty_scan_result_is_valid():
    result = ScanResult(status=ScanStatus.COMPLETE)

    assert result.findings == ()
    assert result.issues == ()
    assert result.target is None
    assert result.metadata == ScanMetadata()
    assert result.summary() == {
        "findings": 0,
        "errors": 0,
        "warnings": 0,
        "by_cwe": {},
        "by_rule": {},
    }


def test_schema_version_is_exposed_and_supported():
    result = ScanResult(status=ScanStatus.COMPLETE)

    assert result.schema_version == SCHEMA_VERSION == "2.0"
    assert SCHEMA_VERSION in SUPPORTED_SCHEMA_VERSIONS


def test_scan_result_is_immutable():
    result = ScanResult(status=ScanStatus.COMPLETE)

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = ScanStatus.FAILED


def test_target_paths_are_normalized_and_may_be_absent():
    assert ScanResult(status=ScanStatus.COMPLETE, target="src\\app").target == (
        "src/app"
    )
    assert ScanResult(status=ScanStatus.COMPLETE, target=None).target is None

    with pytest.raises(ValueError, match="path"):
        ScanResult(status=ScanStatus.COMPLETE, target="")


def test_result_with_multiple_findings():
    findings = assign_occurrences(
        [
            make_finding(location=Location("a.py", 9, 0, 9, 5)),
            make_finding(location=Location("a.py", 2, 0, 2, 5)),
            make_credential_finding(),
        ]
    )
    result = ScanResult(status=ScanStatus.COMPLETE, findings=findings)

    assert len(result.findings) == 3
    assert result.summary()["by_cwe"] == {"CWE-78": 2, "CWE-798": 1}
    assert result.summary()["by_rule"] == {"PY-CMD-001": 2, "PY-SECRET-001": 1}


def test_findings_are_kept_in_canonical_order_whatever_the_input_order():
    findings = assign_occurrences(
        [
            make_finding(location=Location("b.py", 1, 0, 1, 5)),
            make_finding(location=Location("a.py", 7, 0, 7, 5)),
            make_finding(location=Location("a.py", 3, 0, 3, 5)),
        ]
    )

    orders = {
        tuple(
            (f.location.file, f.location.line)
            for f in ScanResult(
                status=ScanStatus.COMPLETE, findings=permutation
            ).findings
        )
        for permutation in itertools.permutations(findings)
    }

    assert orders == {(("a.py", 3), ("a.py", 7), ("b.py", 1))}


def test_duplicate_finding_ids_are_rejected():
    with pytest.raises(ValueError, match="unique finding_id"):
        ScanResult(
            status=ScanStatus.COMPLETE,
            findings=(make_finding(), make_finding()),
        )


def test_findings_must_be_finding_objects():
    with pytest.raises(ValueError, match="Finding"):
        ScanResult(status=ScanStatus.COMPLETE, findings=({"a": 1},))


# ---------------------------------------------------------------
# Issues and status
# ---------------------------------------------------------------


def test_errors_and_warnings_are_separated():
    result = ScanResult(
        status=ScanStatus.PARTIAL,
        issues=(warning_issue(), error_issue()),
    )

    assert [item.code for item in result.errors] == ["syntax-error"]
    assert [item.code for item in result.warnings] == ["skipped"]
    assert result.summary()["errors"] == 1
    assert result.summary()["warnings"] == 1


def test_issues_are_kept_in_canonical_order():
    first = error_issue(file="a.py", line=1)
    second = error_issue(file="b.py", line=1)

    one = ScanResult(status=ScanStatus.PARTIAL, issues=(second, first))
    two = ScanResult(status=ScanStatus.PARTIAL, issues=(first, second))

    assert one.issues == two.issues == (first, second)


def test_complete_scan_may_have_warnings_but_not_errors():
    assert ScanResult(status=ScanStatus.COMPLETE, issues=(warning_issue(),))

    with pytest.raises(ValueError, match="complete scan cannot have error"):
        ScanResult(status=ScanStatus.COMPLETE, issues=(error_issue(),))


@pytest.mark.parametrize("status", [ScanStatus.PARTIAL, ScanStatus.FAILED])
def test_partial_and_failed_scans_need_an_error(status):
    with pytest.raises(ValueError, match="needs an error issue"):
        ScanResult(status=status)

    with pytest.raises(ValueError, match="needs an error issue"):
        ScanResult(status=status, issues=(warning_issue(),))

    assert ScanResult(status=status, issues=(error_issue(),))


def test_failed_scan_may_still_carry_findings():
    result = ScanResult(
        status=ScanStatus.FAILED,
        findings=(make_finding(),),
        issues=(error_issue(),),
    )

    assert len(result.findings) == 1


def test_status_must_be_a_scan_status():
    with pytest.raises(ValueError, match="status"):
        ScanResult(status="complete")


def test_scan_issue_validation():
    with pytest.raises(ValueError, match="level"):
        ScanIssue("error", "code", "message")

    with pytest.raises(ValueError, match="code"):
        ScanIssue(IssueLevel.ERROR, "", "message")

    with pytest.raises(ValueError, match="message"):
        ScanIssue(IssueLevel.ERROR, "code", "")

    with pytest.raises(ValueError, match="line"):
        ScanIssue(IssueLevel.ERROR, "code", "message", line=0)

    assert ScanIssue(IssueLevel.ERROR, "c", "m", file="a\\b.py").file == "a/b.py"


def test_scan_issue_file_and_line_are_optional():
    issue = ScanIssue(IssueLevel.WARNING, "code", "message")

    assert issue.file is None
    assert issue.line is None


# ---------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------


def test_unknown_file_count_is_not_the_same_as_zero_files():
    unknown = ScanMetadata()
    none_scanned = ScanMetadata(files_scanned=0)

    assert unknown.files_scanned is None
    assert none_scanned.files_scanned == 0
    assert unknown != none_scanned


def test_metadata_validation():
    with pytest.raises(ValueError, match="files_scanned"):
        ScanMetadata(files_scanned=-1)

    with pytest.raises(ValueError, match="files_scanned"):
        ScanMetadata(files_scanned=True)

    with pytest.raises(ValueError, match="tool_version"):
        ScanMetadata(tool_version="")


@pytest.mark.parametrize(
    "value",
    ["2026-01-01", "2026-01-01T00:00:00", "2026-01-01 00:00:00Z", "yesterday"],
)
def test_created_at_must_be_a_utc_timestamp(value):
    with pytest.raises(ValueError, match="created_at"):
        ScanMetadata(created_at=value)


def test_created_at_rejects_impossible_dates():
    with pytest.raises(ValueError, match="created_at"):
        ScanMetadata(created_at="2026-13-45T00:00:00Z")


def test_created_at_accepts_utc_timestamps():
    assert ScanMetadata(created_at="2026-01-01T10:20:30Z").created_at
    assert ScanMetadata(created_at="2026-01-01T10:20:30.123456Z").created_at


def test_settings_are_stored_sorted_and_round_trip_to_a_dictionary():
    metadata = ScanMetadata.with_settings({"z": "1", "a": "2"})

    assert metadata.settings == (("a", "2"), ("z", "1"))
    assert metadata.settings_dict() == {"a": "2", "z": "1"}


def test_settings_order_does_not_affect_equality():
    assert ScanMetadata(settings=(("a", "1"), ("b", "2"))) == ScanMetadata(
        settings=(("b", "2"), ("a", "1"))
    )


def test_invalid_settings_are_rejected():
    with pytest.raises(ValueError, match="keys must be unique"):
        ScanMetadata(settings=(("a", "1"), ("a", "2")))

    with pytest.raises(ValueError, match="pairs"):
        ScanMetadata(settings=("ab",))

    with pytest.raises(ValueError, match="setting value"):
        ScanMetadata(settings=(("a", 1),))

    with pytest.raises(ValueError, match="setting key"):
        ScanMetadata(settings=(("", "1"),))


def test_metadata_must_be_scan_metadata():
    with pytest.raises(ValueError, match="metadata"):
        ScanResult(status=ScanStatus.COMPLETE, metadata={"files_scanned": 1})
