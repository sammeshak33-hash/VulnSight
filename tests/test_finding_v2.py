import dataclasses

import pytest
from finding_builders import make_credential_finding, make_finding, make_label

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
)
from vulnsight.scanner.scope import ResolutionCertainty
from vulnsight.scanner.taint_model import SourceKind, TaintEffect

# ---------------------------------------------------------------
# Construction
# ---------------------------------------------------------------


def test_taint_finding_construction():
    finding = make_finding()

    assert finding.rule_id == "PY-CMD-001"
    assert finding.cwe == "CWE-78"
    assert finding.language is Language.PYTHON
    assert finding.sink == Sink("os.system", ResolutionCertainty.DEFINITE)
    assert finding.taint_effect is TaintEffect.RAW
    assert len(finding.evidence) == 1


def test_optional_fields_default_to_unknown():
    finding = Finding(
        rule_id="PY-X-001",
        cwe="CWE-78",
        language=Language.PYTHON,
        message="m",
        location=Location(None, 1, 0),
        confidence=ConfidenceLevel.LOW,
    )

    assert finding.enclosing_function is None
    assert finding.sink is None
    assert finding.evidence == ()
    assert finding.taint_effect is None
    assert finding.severity is None
    assert finding.verification is None
    assert finding.structure_hash is None
    assert finding.occurrence == 0


def test_finding_is_immutable():
    finding = make_finding()

    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.cwe = "CWE-89"


# ---------------------------------------------------------------
# Sink and evidence combinations
# ---------------------------------------------------------------


def test_finding_without_sink_and_without_evidence_is_valid():
    finding = make_credential_finding()

    assert finding.sink is None
    assert finding.evidence == ()


def test_finding_with_sink_and_without_evidence_is_valid():
    finding = make_finding(evidence=(), taint_effect=None)

    assert finding.sink is not None
    assert finding.evidence == ()


def test_evidence_without_sink_is_rejected():
    with pytest.raises(ValueError, match="requires a sink"):
        make_finding(sink=None)


def test_taint_effect_requires_evidence():
    with pytest.raises(ValueError, match="requires taint evidence"):
        make_finding(evidence=(), taint_effect=TaintEffect.RAW)


@pytest.mark.parametrize("effect", [TaintEffect.CLEAN, TaintEffect.NEUTRALIZED])
def test_taint_effect_must_be_raw_partial_or_none(effect):
    with pytest.raises(ValueError, match="RAW, PARTIAL or None"):
        make_finding(taint_effect=effect)


def test_partial_effect_and_unevaluated_effect_are_valid():
    assert make_finding(taint_effect=TaintEffect.PARTIAL).taint_effect is (
        TaintEffect.PARTIAL
    )
    assert make_finding(taint_effect=None).taint_effect is None


def test_evidence_is_stored_in_canonical_order():
    late = make_label(origin_id="sys.argv", kind=SourceKind.CLI_ARG, line=2)
    early = make_label(origin_id="input()", line=9)

    finding = make_finding(evidence=(late, early))

    assert [item.origin.origin_id for item in finding.evidence] == [
        "input()",
        "sys.argv",
    ]


def test_evidence_must_contain_taint_labels():
    with pytest.raises(ValueError, match="TaintLabel"):
        make_finding(evidence=("not a label",))


# ---------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------


@pytest.mark.parametrize("cwe", ["", "78", "CWE-", "CWE-x", "cwe-78", "CWE-78 "])
def test_invalid_cwe_is_rejected(cwe):
    with pytest.raises(ValueError, match="cwe"):
        make_finding(cwe=cwe)


@pytest.mark.parametrize("field", ["rule_id", "message"])
def test_empty_required_text_is_rejected(field):
    with pytest.raises(ValueError, match=field):
        make_finding(**{field: ""})


@pytest.mark.parametrize("separator", ["\x1f", "\x1e"])
def test_reserved_separators_are_rejected_in_hashed_fields(separator):
    with pytest.raises(ValueError, match="reserved separator"):
        make_finding(rule_id=f"PY{separator}X")

    with pytest.raises(ValueError, match="reserved separator"):
        make_finding(enclosing_function=f"f{separator}g")

    with pytest.raises(ValueError, match="reserved separator"):
        Sink(f"os{separator}system", ResolutionCertainty.DEFINITE)

    with pytest.raises(ValueError, match="reserved separator"):
        make_finding(evidence=(make_label(origin_id=f"a{separator}b"),))


def test_reserved_placeholder_names_are_rejected():
    with pytest.raises(ValueError, match="reserved"):
        Sink("<no-sink>", ResolutionCertainty.DEFINITE)

    with pytest.raises(ValueError, match="reserved"):
        make_finding(enclosing_function="<unknown>")


@pytest.mark.parametrize("name", ["<no-sink>", "<unknown>"])
def test_both_reserved_names_are_rejected_as_sink_callees(name):
    with pytest.raises(ValueError, match="reserved"):
        Sink(name, ResolutionCertainty.DEFINITE)

    with pytest.raises(ValueError, match="reserved"):
        Sink(name, ResolutionCertainty.POSSIBLE)


@pytest.mark.parametrize(
    "callee",
    ["os.system", "subprocess.run", "unknown", "no-sink", "<lambda>", "<module>"],
)
def test_legitimate_sink_callees_are_still_accepted(callee):
    assert Sink(callee, ResolutionCertainty.DEFINITE).callee == callee


def test_lone_surrogates_are_rejected():
    with pytest.raises(ValueError, match="valid Unicode"):
        make_finding(message="bad \ud800 text")


def test_module_level_function_name_is_allowed():
    assert make_finding(enclosing_function="<module>").enclosing_function == (
        "<module>"
    )


def test_enum_fields_must_be_enum_members():
    with pytest.raises(ValueError, match="confidence"):
        make_finding(confidence="medium")

    with pytest.raises(ValueError, match="language"):
        make_finding(language="python")


def test_unresolved_sink_certainty_is_rejected():
    with pytest.raises(ValueError, match="resolved"):
        Sink("os.system", ResolutionCertainty.NONE)

    assert Sink("os.system", ResolutionCertainty.POSSIBLE).callee == "os.system"


@pytest.mark.parametrize(
    "value",
    ["", "0123456789ABCDEF0123456789ABCDEF", "abc", "g" * 32, "a" * 33],
)
def test_structure_hash_format_is_enforced(value):
    with pytest.raises(ValueError, match="structure_hash"):
        make_finding(structure_hash=value)


def test_valid_structure_hash_is_accepted():
    finding = make_finding(structure_hash="0123456789abcdef0123456789abcdef")

    assert finding.structure_hash == "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize("value", [-1, True, 1.5, "0"])
def test_occurrence_must_be_a_non_negative_integer(value):
    with pytest.raises(ValueError, match="occurrence"):
        make_finding(occurrence=value)


# ---------------------------------------------------------------
# Location
# ---------------------------------------------------------------


def test_location_normalizes_windows_paths():
    assert Location("src\\app\\run.py", 1, 0).file == "src/app/run.py"


def test_location_allows_missing_file_for_in_memory_source():
    assert Location(None, 1, 0).file is None


@pytest.mark.parametrize(
    "arguments",
    [
        {"file": "", "line": 1, "column": 0},
        {"file": "a.py", "line": 0, "column": 0},
        {"file": "a.py", "line": 1, "column": -1},
        {"file": "a.py", "line": True, "column": 0},
        {"file": "a.py", "line": 5, "column": 0, "end_line": 4},
        {"file": "a.py", "line": 5, "column": 4, "end_line": 5, "end_column": 3},
        {"file": "a.py", "line": 5, "column": 0, "end_column": 3},
        {"file": "a.py", "line": 5, "column": 0, "end_line": 5, "end_column": -1},
    ],
)
def test_invalid_locations_are_rejected(arguments):
    with pytest.raises(ValueError):
        Location(**arguments)


def test_multi_line_location_may_end_in_an_earlier_column():
    location = Location("a.py", 5, 10, 7, 2)

    assert (location.end_line, location.end_column) == (7, 2)


# ---------------------------------------------------------------
# Unknown versus genuine negative
# ---------------------------------------------------------------


def test_not_assessed_severity_differs_from_a_none_level_assessment():
    not_assessed = make_finding()
    assessed_none = make_finding(
        severity=SeverityAssessment(level=SeverityLevel.NONE, method="manual")
    )

    assert not_assessed.severity is None
    assert assessed_none.severity is not None
    assert assessed_none.severity.level is SeverityLevel.NONE
    assert not_assessed != assessed_none


def test_ml_not_run_differs_from_a_kept_verdict():
    not_run = make_finding()
    kept = make_finding(
        verification=Verification(VerificationVerdict.KEPT, 0.9, "model-1")
    )

    assert not_run.verification is None
    assert kept.verification.verdict is VerificationVerdict.KEPT


@pytest.mark.parametrize("score", [-0.01, 10.01, float("nan"), float("inf"), True])
def test_severity_score_must_be_between_zero_and_ten(score):
    with pytest.raises(ValueError, match="score"):
        SeverityAssessment(level=SeverityLevel.LOW, method="m", score=score)


@pytest.mark.parametrize("score", [-0.01, 1.01, float("nan"), True])
def test_verification_score_must_be_between_zero_and_one(score):
    with pytest.raises(ValueError, match="score"):
        Verification(VerificationVerdict.KEPT, score, "model-1")


def test_severity_and_verification_validate_their_text_fields():
    with pytest.raises(ValueError, match="method"):
        SeverityAssessment(level=SeverityLevel.LOW, method="")

    with pytest.raises(ValueError, match="model_id"):
        Verification(VerificationVerdict.KEPT, 0.5, "")

    with pytest.raises(ValueError, match="assumption"):
        SeverityAssessment(level=SeverityLevel.LOW, method="m", assumptions=("",))


def test_finding_rejects_wrong_nested_types():
    with pytest.raises(ValueError, match="severity"):
        make_finding(severity="high")

    with pytest.raises(ValueError, match="verification"):
        make_finding(verification="kept")

    with pytest.raises(ValueError, match="sink"):
        make_finding(sink="os.system")

    with pytest.raises(ValueError, match="location"):
        make_finding(location="a.py:1")


# ---------------------------------------------------------------
# Legacy dictionary-style access
# ---------------------------------------------------------------


def test_legacy_keys_follow_the_v1_meaning():
    finding = make_finding()

    assert finding["function"] == "os.system"
    assert finding["sink"] == "os.system"
    assert finding["line"] == 12
    assert finding["cwe"] == "CWE-78"
    assert finding["rule_id"] == "PY-CMD-001"
    assert finding["message"] == "Potential command injection"
    assert finding["confidence"] == "medium"
    assert finding["severity"] == "Review required"
    assert finding["source"] == "input()"


def test_legacy_severity_reports_the_assessed_level():
    finding = make_finding(
        severity=SeverityAssessment(level=SeverityLevel.HIGH, method="m")
    )

    assert finding["severity"] == "high"


def test_legacy_access_without_a_sink_returns_empty_strings():
    finding = make_credential_finding()

    assert finding["function"] == ""
    assert finding["sink"] == ""
    assert finding["source"] == ""


def test_legacy_source_lists_every_origin_once():
    finding = make_finding(
        evidence=(
            make_label(origin_id="input()", line=1),
            make_label(origin_id="input()", line=5),
            make_label(origin_id="sys.argv", kind=SourceKind.CLI_ARG, line=3),
        )
    )

    assert finding["source"] == "input(), sys.argv"


def test_legacy_get_returns_default_for_unknown_keys():
    finding = make_finding()

    assert finding.get("unknown", "default") == "default"
    assert finding.get("unknown") is None
    assert finding.get("cwe") == "CWE-78"
    assert finding.get("location") is None


def test_legacy_getitem_raises_key_error_for_unknown_keys():
    with pytest.raises(KeyError):
        make_finding()["location"]


# ---------------------------------------------------------------
# SeverityAssessment.assumptions
# ---------------------------------------------------------------


def test_assumptions_accept_a_tuple_of_strings():
    assessment = SeverityAssessment(
        level=SeverityLevel.LOW, method="m", assumptions=("local attacker", "no auth")
    )

    assert assessment.assumptions == ("local attacker", "no auth")


def test_assumptions_default_and_empty_tuple_are_valid():
    default = SeverityAssessment(level=SeverityLevel.LOW, method="m")
    empty = SeverityAssessment(level=SeverityLevel.LOW, method="m", assumptions=())

    assert default.assumptions == ()
    assert empty.assumptions == ()


def test_assumptions_list_is_normalized_to_a_tuple():
    assessment = SeverityAssessment(
        level=SeverityLevel.LOW, method="m", assumptions=["a", "b"]
    )

    assert assessment.assumptions == ("a", "b")
    assert isinstance(assessment.assumptions, tuple)


def test_a_bare_string_is_rejected_instead_of_split_into_characters():
    with pytest.raises(ValueError, match="tuple or list of strings"):
        SeverityAssessment(level=SeverityLevel.LOW, method="m", assumptions="abc")


@pytest.mark.parametrize("value", [b"abc", bytearray(b"abc"), b""])
def test_bytes_are_rejected_as_assumptions(value):
    with pytest.raises(ValueError, match="tuple or list of strings"):
        SeverityAssessment(level=SeverityLevel.LOW, method="m", assumptions=value)


@pytest.mark.parametrize("value", [5, None, {"a"}, {"a": 1}, object()])
def test_other_container_types_are_rejected_as_assumptions(value):
    with pytest.raises(ValueError, match="tuple or list of strings"):
        SeverityAssessment(level=SeverityLevel.LOW, method="m", assumptions=value)


@pytest.mark.parametrize("item", ["", 5, None, b"x"])
def test_invalid_assumption_elements_are_rejected(item):
    with pytest.raises(ValueError, match="assumption"):
        SeverityAssessment(
            level=SeverityLevel.LOW, method="m", assumptions=("ok", item)
        )


def test_assessment_stays_immutable_after_validation():
    assessment = SeverityAssessment(
        level=SeverityLevel.LOW, method="m", assumptions=("a",)
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        assessment.assumptions = ("b",)


# ---------------------------------------------------------------
# Oversized integer scores
# ---------------------------------------------------------------

OVERSIZED_INTEGERS = [10**400, -(10**400), 2**1024, -(2**1024)]
OVERSIZED_IDS = ["+10**400", "-10**400", "+2**1024", "-2**1024"]


@pytest.mark.parametrize("score", OVERSIZED_INTEGERS, ids=OVERSIZED_IDS)
def test_severity_score_too_large_for_a_float_raises_value_error(score):
    with pytest.raises(ValueError, match="score must be between 0 and 10"):
        SeverityAssessment(level=SeverityLevel.LOW, method="m", score=score)


@pytest.mark.parametrize("score", OVERSIZED_INTEGERS, ids=OVERSIZED_IDS)
def test_verification_score_too_large_for_a_float_raises_value_error(score):
    with pytest.raises(ValueError, match="score must be between 0 and 1"):
        Verification(VerificationVerdict.KEPT, score, "model-1")


def test_oversized_scores_do_not_raise_overflow_error():
    for build in (
        lambda: SeverityAssessment(level=SeverityLevel.LOW, method="m", score=10**400),
        lambda: Verification(VerificationVerdict.KEPT, -(10**400), "m"),
    ):
        try:
            build()
        except OverflowError:
            pytest.fail("OverflowError leaked from a constructor")
        except ValueError:
            pass


def test_large_but_convertible_integer_scores_get_the_range_error():
    with pytest.raises(ValueError, match="between 0 and 10"):
        SeverityAssessment(level=SeverityLevel.LOW, method="m", score=10**308)

    with pytest.raises(ValueError, match="between 0 and 1"):
        Verification(VerificationVerdict.KEPT, 10**308, "m")


@pytest.mark.parametrize("score", [0, 5, 10, 0.0, 7.25, 10.0])
def test_normal_severity_scores_are_still_accepted_as_floats(score):
    assessment = SeverityAssessment(level=SeverityLevel.LOW, method="m", score=score)

    assert assessment.score == float(score)
    assert isinstance(assessment.score, float)


@pytest.mark.parametrize("score", [0, 1, 0.5, 1.0])
def test_normal_verification_scores_are_still_accepted_as_floats(score):
    verification = Verification(VerificationVerdict.KEPT, score, "m")

    assert verification.score == float(score)
    assert isinstance(verification.score, float)
