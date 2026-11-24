import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from finding_builders import (
    golden_scan_result,
    make_credential_finding,
    make_finding,
    make_label,
)

from vulnsight.codec import SchemaError, loads_strict
from vulnsight.findings import (
    ConfidenceLevel,
    Finding,
    Language,
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
    MAX_TRACE_STEPS,
    Neutralization,
    SourceKind,
    TaintEffect,
    TraceKind,
)

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = Path(__file__).with_name("golden") / "scan_result_v2.json"


def read_golden():
    # Git on Windows may check files out with CRLF; the contract is LF.
    text = GOLDEN.read_bytes().decode("utf-8").replace("\r\n", "\n")

    return text.rstrip("\n")


def golden_data():
    return json.loads(read_golden())


# ---------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------


def test_taint_finding_round_trip():
    finding = make_finding()

    assert Finding.from_dict(finding.to_dict()) == finding


def test_non_taint_finding_round_trip_keeps_nulls():
    finding = make_credential_finding()
    data = finding.to_dict()

    assert data["sink"] is None
    assert data["evidence"] == []
    assert data["evidence_signature"] is None
    assert Finding.from_dict(data) == finding


def test_fully_populated_finding_round_trip():
    finding = make_finding(
        severity=SeverityAssessment(
            level=SeverityLevel.NONE,
            method="manual",
            score=0.0,
            vector="CVSS:4.0/AV:L",
            assumptions=("a", "b"),
        ),
        verification=Verification(VerificationVerdict.SUPPRESSED, 0.25, "m-1"),
        structure_hash="0123456789abcdef0123456789abcdef",
        occurrence=4,
    )

    assert Finding.from_dict(finding.to_dict()) == finding


def test_nested_trace_and_neutralization_data_are_preserved():
    label = make_label(
        steps=(TraceKind.CONCAT, TraceKind.CALL, TraceKind.PARTIAL_SANITIZER),
        neutralizations=(
            Neutralization("CWE-78", frozenset({"posix", "windows"}), "int"),
            Neutralization("*", frozenset({"posix"}), "len"),
        ),
    )
    finding = make_finding(evidence=(label,), taint_effect=TaintEffect.PARTIAL)

    loaded = Finding.from_dict(finding.to_dict())

    assert loaded.evidence == finding.evidence
    assert [step.kind for step in loaded.evidence[0].trace] == [
        TraceKind.SOURCE,
        TraceKind.CONCAT,
        TraceKind.CALL,
        TraceKind.PARTIAL_SANITIZER,
    ]
    assert loaded.evidence[0].neutralizations == label.neutralizations


def test_scan_result_dict_and_json_round_trip():
    result = golden_scan_result()

    assert ScanResult.from_dict(result.to_dict()) == result
    assert ScanResult.from_json(result.to_json()) == result


def test_empty_scan_result_round_trip():
    result = ScanResult(status=ScanStatus.COMPLETE)

    assert ScanResult.from_json(result.to_json()) == result


def test_failed_scan_with_errors_round_trip():
    result = ScanResult(
        status=ScanStatus.FAILED,
        target="src",
        issues=(ScanIssue(IssueLevel.ERROR, "io-error", "Cannot read", "a.py", 1),),
        metadata=ScanMetadata(files_scanned=None),
    )

    loaded = ScanResult.from_json(result.to_json())

    assert loaded == result
    assert loaded.metadata.files_scanned is None


def test_unknown_and_zero_file_counts_survive_the_round_trip():
    unknown = ScanResult(status=ScanStatus.COMPLETE)
    zero = ScanResult(
        status=ScanStatus.COMPLETE, metadata=ScanMetadata(files_scanned=0)
    )

    assert ScanResult.from_json(unknown.to_json()).metadata.files_scanned is None
    assert ScanResult.from_json(zero.to_json()).metadata.files_scanned == 0


# ---------------------------------------------------------------
# Every enum value serializes
# ---------------------------------------------------------------


@pytest.mark.parametrize("kind", list(SourceKind))
def test_every_source_kind_round_trips(kind):
    label = make_label(origin_id=f"origin-{kind.value}", kind=kind)
    finding = make_finding(evidence=(label,))

    loaded = Finding.from_dict(finding.to_dict())

    assert loaded.evidence[0].origin.kind is kind


@pytest.mark.parametrize("kind", list(TraceKind))
def test_every_trace_kind_round_trips(kind):
    if kind is TraceKind.SOURCE:
        steps = ()
    else:
        steps = (kind,)

    finding = make_finding(evidence=(make_label(steps=steps),))

    assert Finding.from_dict(finding.to_dict()) == finding


@pytest.mark.parametrize("effect", [TaintEffect.RAW, TaintEffect.PARTIAL, None])
def test_taint_effect_values_round_trip(effect):
    finding = make_finding(taint_effect=effect)

    assert Finding.from_dict(finding.to_dict()).taint_effect is effect


@pytest.mark.parametrize(
    "certainty", [ResolutionCertainty.DEFINITE, ResolutionCertainty.POSSIBLE]
)
def test_sink_certainty_round_trips(certainty):
    finding = make_finding(sink=Sink("os.system", certainty))

    assert Finding.from_dict(finding.to_dict()).sink.certainty is certainty


@pytest.mark.parametrize("language", list(Language))
def test_every_language_round_trips(language):
    finding = make_finding(language=language)

    assert Finding.from_dict(finding.to_dict()).language is language


@pytest.mark.parametrize("level", list(ConfidenceLevel))
def test_every_confidence_level_round_trips(level):
    finding = make_finding(confidence=level)

    assert Finding.from_dict(finding.to_dict()).confidence is level


@pytest.mark.parametrize("level", list(SeverityLevel))
def test_every_severity_level_round_trips(level):
    finding = make_finding(severity=SeverityAssessment(level=level, method="m"))

    assert Finding.from_dict(finding.to_dict()).severity.level is level


@pytest.mark.parametrize("verdict", list(VerificationVerdict))
def test_every_verification_verdict_round_trips(verdict):
    finding = make_finding(verification=Verification(verdict, 0.5, "m"))

    assert Finding.from_dict(finding.to_dict()).verification.verdict is verdict


@pytest.mark.parametrize("level", list(IssueLevel))
def test_every_issue_level_round_trips(level):
    status = ScanStatus.PARTIAL if level is IssueLevel.ERROR else ScanStatus.COMPLETE
    issues = [ScanIssue(level, "c", "m")]

    if status is ScanStatus.PARTIAL:
        issues = [ScanIssue(IssueLevel.ERROR, "c", "m")]

    result = ScanResult(status=status, issues=tuple(issues))

    assert ScanResult.from_json(result.to_json()) == result


@pytest.mark.parametrize("status", list(ScanStatus))
def test_every_scan_status_round_trips(status):
    issues = ()

    if status is not ScanStatus.COMPLETE:
        issues = (ScanIssue(IssueLevel.ERROR, "c", "m"),)

    result = ScanResult(status=status, issues=issues)

    assert ScanResult.from_json(result.to_json()).status is status


# ---------------------------------------------------------------
# Enum value pins: a deliberate gate for schema compatibility
# ---------------------------------------------------------------

PINNED_ENUM_VALUES = {
    SourceKind: {
        "interactive",
        "stdin",
        "cli_arg",
        "environment",
        "framework",
        "file",
        "network",
        "parameter",
    },
    TraceKind: {
        "source",
        "assign",
        "concat",
        "format",
        "call",
        "alias",
        "container",
        "loop",
        "partial_sanitizer",
        "elided",
    },
    TaintEffect: {"clean", "raw", "partial", "neutralized"},
    ResolutionCertainty: {"definite", "possible", "none"},
    Language: {"python", "c", "cpp"},
    ConfidenceLevel: {"low", "medium", "high"},
    SeverityLevel: {"none", "low", "medium", "high", "critical"},
    VerificationVerdict: {"kept", "suppressed"},
    ScanStatus: {"complete", "partial", "failed"},
    IssueLevel: {"error", "warning"},
}


@pytest.mark.parametrize(
    "enum_type", list(PINNED_ENUM_VALUES), ids=lambda e: e.__name__
)
def test_serialized_enum_values_are_pinned(enum_type):
    actual = {member.value for member in enum_type}

    assert actual == PINNED_ENUM_VALUES[enum_type], (
        f"{enum_type.__name__} changed. Before updating this pin, assess "
        "compatibility as described under 'Schema versioning' in "
        "docs/finding-schema.md: decide whether SCHEMA_VERSION changes, "
        "record the decision in the schema changelog, then update this table."
    )


# ---------------------------------------------------------------
# Deterministic output
# ---------------------------------------------------------------


def test_to_json_is_repeatable():
    result = golden_scan_result()

    assert result.to_json() == result.to_json()


def test_json_is_identical_after_a_round_trip():
    result = golden_scan_result()

    assert ScanResult.from_json(result.to_json()).to_json() == result.to_json()


def test_json_does_not_depend_on_input_ordering():
    findings = list(golden_scan_result().findings)
    forward = ScanResult(status=ScanStatus.COMPLETE, findings=findings)
    backward = ScanResult(status=ScanStatus.COMPLETE, findings=findings[::-1])

    assert forward.to_json() == backward.to_json()


def test_json_is_ascii_with_sorted_keys_and_lf_line_endings():
    text = golden_scan_result().to_json()

    assert text.isascii()
    assert "\r" not in text
    assert text == json.dumps(
        json.loads(text), sort_keys=True, indent=2, ensure_ascii=True
    )


def test_json_matches_the_golden_file_byte_for_byte():
    assert golden_scan_result().to_json() == read_golden()


def test_golden_file_loads_back_to_the_same_result():
    assert ScanResult.from_json(read_golden()) == golden_scan_result()


def test_output_is_independent_of_python_hash_randomization():
    script = (
        "import sys;"
        f"sys.path[:0]=[{str(ROOT)!r}, {str(ROOT / 'tests')!r}];"
        "from finding_builders import golden_scan_result;"
        "sys.stdout.write(golden_scan_result().to_json())"
    )
    outputs = set()

    for seed in ("1", "2", "12345"):
        environment = {**os.environ, "PYTHONHASHSEED": seed}
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            check=True,
            env=environment,
            text=True,
        )
        outputs.add(completed.stdout)

    assert outputs == {read_golden()}


def test_derived_identifiers_are_emitted():
    data = golden_data()
    finding = data["findings"][1]

    assert set(("fingerprint", "evidence_signature", "finding_id")) <= set(finding)
    assert data["schema_version"] == "2.1"
    assert data["summary"]["findings"] == 4


def test_timestamp_is_absent_unless_the_caller_sets_one():
    result = ScanResult(status=ScanStatus.COMPLETE)

    assert json.loads(result.to_json())["metadata"]["created_at"] is None


# ---------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        "{",
        "[]",
        "null",
        "42",
        '"text"',
        '{"schema_version": NaN}',
        '{"schema_version": Infinity}',
        '{"schema_version": -Infinity}',
    ],
)
def test_malformed_json_text_is_rejected(text):
    with pytest.raises(SchemaError):
        ScanResult.from_json(text)


def test_non_string_json_input_is_rejected():
    with pytest.raises(SchemaError, match="string"):
        ScanResult.from_json(b"{}")


def test_deeply_nested_json_is_rejected_cleanly():
    with pytest.raises(SchemaError):
        ScanResult.from_json("[" * 100000)


def test_schema_error_is_a_value_error():
    assert issubclass(SchemaError, ValueError)


def test_unsupported_schema_versions_are_rejected():
    for version in ("1.0", "2.2", "3.0", "", "2"):
        data = golden_data()
        data["schema_version"] = version

        with pytest.raises(SchemaError, match="schema_version"):
            ScanResult.from_dict(data)


def test_non_string_schema_version_is_rejected():
    data = golden_data()
    data["schema_version"] = 2

    with pytest.raises(SchemaError, match="schema_version"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize(
    "key",
    ["schema_version", "target", "status", "findings", "issues", "metadata", "summary"],
)
def test_missing_top_level_keys_are_rejected(key):
    data = golden_data()
    del data[key]

    with pytest.raises(SchemaError, match=key):
        ScanResult.from_dict(data)


@pytest.mark.parametrize(
    "key",
    [
        "rule_id",
        "cwe",
        "language",
        "message",
        "location",
        "confidence",
        "enclosing_function",
        "sink",
        "evidence",
        "taint_effect",
        "severity",
        "verification",
        "structure_hash",
        "occurrence",
        "fingerprint",
        "evidence_signature",
        "finding_id",
    ],
)
def test_missing_finding_keys_are_rejected(key):
    data = golden_data()
    del data["findings"][1][key]

    with pytest.raises(SchemaError, match=rf"findings\[1\]\.{key}"):
        ScanResult.from_dict(data)


def test_unknown_keys_are_rejected_at_every_level():
    locations = [
        lambda d: d,
        lambda d: d["findings"][1],
        lambda d: d["findings"][1]["location"],
        lambda d: d["findings"][1]["sink"],
        lambda d: d["findings"][1]["evidence"][0],
        lambda d: d["findings"][1]["evidence"][0]["origin"],
        lambda d: d["findings"][1]["evidence"][0]["trace"][0],
        lambda d: d["findings"][2]["evidence"][0]["neutralizations"][0],
        lambda d: d["findings"][0]["severity"] or d["findings"][3]["severity"],
        lambda d: d["findings"][3]["verification"],
        lambda d: d["issues"][0],
        lambda d: d["metadata"],
    ]

    for locate in locations:
        data = golden_data()
        locate(data)["surprise"] = 1

        with pytest.raises(SchemaError, match="unknown keys: surprise"):
            ScanResult.from_dict(data)


@pytest.mark.parametrize(
    "mutate, path",
    [
        (lambda d: d["findings"][1]["location"].update(line="12"), "location.line"),
        (lambda d: d["findings"][1]["location"].update(line=True), "location.line"),
        (lambda d: d["findings"][1]["location"].update(line=12.0), "location.line"),
        (lambda d: d["findings"][1].update(rule_id=5), "rule_id"),
        (lambda d: d["findings"][1].update(occurrence="0"), "occurrence"),
        (lambda d: d["findings"][1].update(evidence={}), "evidence"),
        (lambda d: d["findings"][1].update(location=[]), "location"),
        (lambda d: d["findings"][1].update(sink="os.system"), "sink"),
        (lambda d: d["metadata"].update(files_scanned="3"), "files_scanned"),
        (lambda d: d["metadata"].update(settings=[]), "settings"),
        (lambda d: d["metadata"]["settings"].update(a=1), "settings.a"),
        (lambda d: d["issues"][0].update(line="4"), "issues[0].line"),
        (lambda d: d.update(findings={}), "findings"),
        (lambda d: d.update(target=5), "target"),
    ],
)
def test_wrong_types_are_rejected_with_a_path(mutate, path):
    data = golden_data()
    mutate(data)

    with pytest.raises(SchemaError, match=path.replace("[", r"\[").replace("]", r"\]")):
        ScanResult.from_dict(data)


@pytest.mark.parametrize(
    "mutate, path",
    [
        (lambda d: d["findings"][1].update(language="cobol"), "language"),
        (lambda d: d["findings"][1].update(confidence="certain"), "confidence"),
        (lambda d: d["findings"][1]["sink"].update(certainty="maybe"), "certainty"),
        (lambda d: d["findings"][1].update(taint_effect="mostly"), "taint_effect"),
        (
            lambda d: d["findings"][1]["evidence"][0]["origin"].update(
                kind="telepathy"
            ),
            r"findings\[1\]\.evidence\[0\]\.origin\.kind",
        ),
        (
            lambda d: d["findings"][1]["evidence"][0]["trace"][1].update(kind="warp"),
            r"trace\[1\]\.kind",
        ),
        (lambda d: d["findings"][3]["severity"].update(level="extreme"), "level"),
        (lambda d: d["findings"][3]["verification"].update(verdict="maybe"), "verdict"),
        (lambda d: d["issues"][0].update(level="fatal"), r"issues\[0\]\.level"),
        (lambda d: d.update(status="done"), "status"),
    ],
)
def test_unknown_enum_values_are_rejected_with_a_path(mutate, path):
    data = golden_data()
    mutate(data)

    with pytest.raises(SchemaError, match=path):
        ScanResult.from_dict(data)


def test_enum_errors_list_the_allowed_values():
    data = golden_data()
    data["findings"][1]["confidence"] = "certain"

    with pytest.raises(SchemaError, match="high, low, medium"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("key", ["fingerprint", "evidence_signature", "finding_id"])
def test_tampered_derived_identifiers_are_rejected(key):
    data = golden_data()
    data["findings"][1][key] = "0" * 32

    with pytest.raises(SchemaError, match=f"{key}: does not match"):
        ScanResult.from_dict(data)


def test_tampered_content_with_stale_identifiers_is_rejected():
    data = golden_data()
    data["findings"][1]["sink"]["callee"] = "os.popen"

    with pytest.raises(SchemaError, match="does not match"):
        ScanResult.from_dict(data)


def test_tampered_summary_is_rejected():
    data = golden_data()
    data["summary"]["findings"] = 99

    with pytest.raises(SchemaError, match="summary"):
        ScanResult.from_dict(data)


def test_invariant_violations_surface_as_schema_errors():
    data = golden_data()
    data["findings"][1]["sink"] = None

    with pytest.raises(SchemaError, match="requires a sink"):
        ScanResult.from_dict(data)


def test_status_that_contradicts_issues_is_rejected():
    data = golden_data()
    data["status"] = "failed"

    with pytest.raises(SchemaError, match="needs an error issue"):
        ScanResult.from_dict(data)


def test_duplicate_finding_ids_in_json_are_rejected():
    data = golden_data()
    data["findings"].append(copy.deepcopy(data["findings"][0]))
    data["summary"]["findings"] = 5
    data["summary"]["by_cwe"]["CWE-798"] = 2
    data["summary"]["by_rule"]["PY-SECRET-001"] = 2

    with pytest.raises(SchemaError, match="unique finding_id"):
        ScanResult.from_dict(data)


def test_trace_longer_than_the_model_limit_is_rejected_not_truncated():
    data = golden_data()
    trace = data["findings"][1]["evidence"][0]["trace"]
    trace.extend(
        {"kind": "assign", "line": 20, "col": 0, "text": "x"}
        for _ in range(MAX_TRACE_STEPS)
    )

    with pytest.raises(SchemaError, match="more than"):
        ScanResult.from_dict(data)


def test_overlong_trace_text_is_rejected_not_truncated():
    data = golden_data()
    data["findings"][1]["evidence"][0]["trace"][0]["text"] = "x" * 500

    with pytest.raises(SchemaError, match="longer than the model allows"):
        ScanResult.from_dict(data)


def test_trace_must_start_with_a_source_step():
    data = golden_data()
    data["findings"][1]["evidence"][0]["trace"][0]["kind"] = "assign"

    with pytest.raises(SchemaError, match="SOURCE"):
        ScanResult.from_dict(data)


def test_invalid_neutralizations_are_rejected():
    data = golden_data()
    neutralization = data["findings"][2]["evidence"][0]["neutralizations"][0]

    bad_platform = copy.deepcopy(data)
    bad_platform["findings"][2]["evidence"][0]["neutralizations"][0]["platforms"] = [
        "plan9"
    ]

    with pytest.raises(SchemaError, match="posix and/or windows"):
        ScanResult.from_dict(bad_platform)

    duplicated = copy.deepcopy(data)
    duplicated["findings"][2]["evidence"][0]["neutralizations"] = [
        neutralization,
        neutralization,
    ]

    with pytest.raises(SchemaError, match="duplicate"):
        ScanResult.from_dict(duplicated)

    repeated_platform = copy.deepcopy(data)
    repeated_platform["findings"][2]["evidence"][0]["neutralizations"][0][
        "platforms"
    ] = ["posix", "posix"]

    with pytest.raises(SchemaError, match="duplicate platforms"):
        ScanResult.from_dict(repeated_platform)


@pytest.mark.parametrize("score", [-1, 10.5, 11])
def test_out_of_range_severity_scores_in_json_are_rejected(score):
    data = golden_data()
    data["findings"][3]["severity"]["score"] = score

    with pytest.raises(SchemaError, match="score must be between 0 and 10"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("score", [-0.1, 1.5, 2])
def test_out_of_range_verification_scores_in_json_are_rejected(score):
    data = golden_data()
    data["findings"][3]["verification"]["score"] = score

    with pytest.raises(SchemaError, match="score must be between 0 and 1"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("big", [10**400, -(10**400), 2**1024, -(2**1024)])
@pytest.mark.parametrize(
    "locate, path",
    [
        (lambda d: d["findings"][3]["severity"], r"findings\[3\]\.severity\.score"),
        (
            lambda d: d["findings"][3]["verification"],
            r"findings\[3\]\.verification\.score",
        ),
    ],
)
def test_integers_too_large_for_a_float_raise_schema_error_with_a_path(
    big, locate, path
):
    data = golden_data()
    locate(data)["score"] = big

    with pytest.raises(SchemaError, match=f"{path}: expected a finite number"):
        ScanResult.from_dict(data)


def test_large_but_convertible_integers_still_get_the_range_error():
    data = golden_data()
    data["findings"][3]["severity"]["score"] = 10**308

    with pytest.raises(SchemaError, match="score must be between 0 and 10"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_non_finite_floats_in_dict_input_keep_their_message(value):
    data = golden_data()
    data["findings"][3]["severity"]["score"] = value

    with pytest.raises(
        SchemaError, match=r"findings\[3\]\.severity\.score: expected a finite"
    ):
        ScanResult.from_dict(data)


def test_booleans_are_still_not_numbers_in_dict_input():
    data = golden_data()
    data["findings"][3]["verification"]["score"] = True

    with pytest.raises(SchemaError, match=r"verification\.score: expected a number"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("value", [0, 5, 10, 0.0, 7.25, 10.0])
def test_normal_integers_and_floats_still_load_as_scores(value):
    data = golden_data()
    data["findings"][3]["severity"]["score"] = value
    loaded = ScanResult.from_dict(data)

    assert loaded.findings[3].severity.score == float(value)
    assert isinstance(loaded.findings[3].severity.score, float)


def test_non_finite_numbers_in_dict_input_are_rejected():
    data = golden_data()
    data["findings"][3]["verification"]["score"] = float("nan")

    with pytest.raises(SchemaError, match="finite"):
        ScanResult.from_dict(data)


def test_lone_surrogates_in_json_text_are_rejected_cleanly():
    text = read_golden().replace("Hard-coded credential", "bad \\ud800 text")

    with pytest.raises(SchemaError, match="valid Unicode"):
        ScanResult.from_json(text)


def test_bad_timestamps_and_settings_in_json_are_rejected():
    data = golden_data()
    data["metadata"]["created_at"] = "yesterday"

    with pytest.raises(SchemaError, match="created_at"):
        ScanResult.from_dict(data)


def test_non_object_findings_are_rejected_with_their_index():
    data = golden_data()
    data["findings"][2] = "not an object"

    with pytest.raises(SchemaError, match=r"findings\[2\]: expected an object"):
        ScanResult.from_dict(data)


def test_findings_loaded_from_json_are_validated_like_constructed_ones():
    data = golden_data()
    data["findings"][1]["cwe"] = "78"

    with pytest.raises(SchemaError, match="cwe"):
        ScanResult.from_dict(data)


def test_assign_occurrences_output_round_trips_through_json():
    findings = assign_occurrences([make_finding(), make_credential_finding()])
    result = ScanResult(status=ScanStatus.COMPLETE, findings=findings)

    assert ScanResult.from_json(result.to_json()) == result


# ---------------------------------------------------------------
# Duplicate JSON object keys
# ---------------------------------------------------------------


def with_duplicate(anchor, duplicate, text=None):
    """Insert ``duplicate`` right after the first occurrence of ``anchor``."""

    text = read_golden() if text is None else text

    assert text.count(anchor) >= 1, anchor

    return text.replace(anchor, anchor + duplicate, 1)


def test_duplicate_top_level_key_is_rejected():
    text = with_duplicate('"status": "complete",', ' "status": "failed",')

    with pytest.raises(SchemaError, match="duplicate key 'status'"):
        ScanResult.from_json(text)


@pytest.mark.parametrize(
    "anchor, duplicate, key",
    [
        ('"schema_version": "2.1",', ' "schema_version": "2.1",', "schema_version"),
        ('"line": 12', ', "line": 99', "line"),
        ('"origin_id": "input()"', ', "origin_id": "other()"', "origin_id"),
        ('"callee": "os.system"', ', "callee": "os.popen"', "callee"),
        (
            '"parameter_mode": "strict"',
            ', "parameter_mode": "recall"',
            "parameter_mode",
        ),
        ('"level": "warning"', ', "level": "error"', "level"),
        ('"model_id": "example-model"', ', "model_id": "x"', "model_id"),
    ],
)
def test_duplicate_nested_keys_are_rejected_at_every_level(anchor, duplicate, key):
    text = with_duplicate(anchor, duplicate)

    with pytest.raises(SchemaError, match=f"duplicate key '{key}'"):
        ScanResult.from_json(text)


def test_duplicate_with_the_same_value_is_still_rejected():
    text = with_duplicate('"status": "complete",', ' "status": "complete",')

    with pytest.raises(SchemaError, match="duplicate key 'status'"):
        ScanResult.from_json(text)


def test_keys_that_are_equal_after_unescaping_count_as_duplicates():
    text = with_duplicate('"status": "complete",', ' "\\u0073tatus": "failed",')

    with pytest.raises(SchemaError, match="duplicate key 'status'"):
        ScanResult.from_json(text)


def test_duplicate_keys_inside_array_elements_are_rejected():
    text = '{"findings": [{"a": 1}, {"b": 1, "b": 2}]}'

    with pytest.raises(SchemaError, match="duplicate key 'b'"):
        ScanResult.from_json(text)


def test_same_key_in_different_objects_is_not_a_duplicate():
    # "line" appears in many separate objects of the golden file.
    assert read_golden().count('"line"') > 5
    assert ScanResult.from_json(read_golden()) == golden_scan_result()


def test_unique_keys_continue_to_load_after_the_check():
    result = golden_scan_result()

    assert ScanResult.from_json(result.to_json()) == result


def test_duplicate_key_check_keeps_the_other_json_rejections():
    for text in ('{"a": NaN}', '{"a": Infinity}', "{", "[" * 100000):
        with pytest.raises(SchemaError):
            ScanResult.from_json(text)


def test_canonical_output_is_unchanged_by_the_duplicate_key_check():
    assert golden_scan_result().to_json() == read_golden()


# ---------------------------------------------------------------
# Integers beyond Python's digit limit
# ---------------------------------------------------------------


def digit_limit():
    limit = sys.get_int_max_str_digits()

    if limit == 0:
        pytest.skip("Python's integer digit limit is disabled in this interpreter")

    return limit


def test_integer_over_the_digit_limit_raises_schema_error():
    digits = "1" * (digit_limit() + 1)

    with pytest.raises(SchemaError, match="invalid JSON") as caught:
        ScanResult.from_json('{"schema_version": ' + digits + "}")

    assert not isinstance(caught.value, json.JSONDecodeError)
    assert str(digit_limit()) in str(caught.value)


@pytest.mark.parametrize("sign", ["", "-"])
def test_oversized_integers_are_rejected_wherever_they_appear(sign):
    digits = sign + "9" * (digit_limit() + 1)
    nested = read_golden().replace('"line": 12', f'"line": {digits}', 1)

    for text in (
        "[" + digits + "]",
        '{"a": {"b": [' + digits + "]}}",
        nested,
    ):
        with pytest.raises(SchemaError, match="invalid JSON"):
            ScanResult.from_json(text)

    with pytest.raises(SchemaError, match="invalid JSON"):
        loads_strict(digits)


def test_integer_exactly_at_the_digit_limit_still_parses():
    value = loads_strict("9" * digit_limit())

    assert isinstance(value, int)


def test_digit_limit_is_not_changed_by_the_check():
    before = sys.get_int_max_str_digits()

    with pytest.raises(SchemaError):
        loads_strict("1" * (digit_limit() + 1))

    assert sys.get_int_max_str_digits() == before


def test_our_own_parse_errors_are_not_wrapped_twice():
    with pytest.raises(SchemaError) as duplicate:
        loads_strict('{"a": 1, "a": 2}')

    with pytest.raises(SchemaError) as constant:
        loads_strict('{"a": NaN}')

    assert str(duplicate.value) == "invalid JSON: duplicate key 'a'"
    assert str(constant.value) == "invalid JSON constant: NaN"


def test_other_json_failures_are_still_schema_errors_after_the_change():
    for text in ("", "{", "[1,", '{"a": }', "[" * 100000, '{"a": Infinity}'):
        with pytest.raises(SchemaError):
            loads_strict(text)
