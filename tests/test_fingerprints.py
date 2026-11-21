import hashlib
import itertools
from dataclasses import replace

import pytest
from finding_builders import make_credential_finding, make_finding, make_label

from vulnsight.findings import (
    Finding,
    Location,
    Sink,
    assign_occurrences,
    short_hash,
)
from vulnsight.scanner.scope import ResolutionCertainty
from vulnsight.scanner.taint_model import SourceKind, TraceKind

DEFINITE = ResolutionCertainty.DEFINITE


def sink(callee):
    return Sink(callee, DEFINITE)


# ---------------------------------------------------------------
# short_hash
# ---------------------------------------------------------------


def test_short_hash_is_32_lowercase_hex_characters():
    value = short_hash("prefix", "a", "b")

    assert len(value) == 32
    assert value == value.lower()
    int(value, 16)


def test_short_hash_keeps_field_boundaries_unambiguous():
    assert short_hash("p", "ab", "c") != short_hash("p", "a", "bc")
    assert short_hash("p", "a") != short_hash("p", "a", "a")


def test_short_hash_rejects_the_field_separator_and_empty_parts():
    with pytest.raises(ValueError, match="separator"):
        short_hash("p", "a\x1fb")

    with pytest.raises(ValueError, match="hash part"):
        short_hash("p", "")


# ---------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------


def test_fingerprint_ignores_line_column_and_file():
    base = make_finding()
    moved = make_finding(location=Location("other/dir/file.py", 400, 9, 400, 40))

    assert moved.fingerprint == base.fingerprint


def test_fingerprint_ignores_message_confidence_and_evidence_details():
    base = make_finding()
    changed = make_finding(
        message="Different wording",
        evidence=(make_label(line=99, steps=(TraceKind.CONCAT, TraceKind.CALL)),),
    )

    assert changed.fingerprint == base.fingerprint


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule_id": "PY-CMD-002"},
        {"cwe": "CWE-77"},
        {"sink": sink("os.popen")},
        {"enclosing_function": "other"},
    ],
)
def test_fingerprint_changes_with_each_identity_field(overrides):
    assert make_finding(**overrides).fingerprint != make_finding().fingerprint


def test_fingerprint_is_deterministic_and_has_the_expected_shape():
    first = make_finding().fingerprint

    assert first == make_finding().fingerprint
    assert len(first) == 32


def test_fingerprint_value_is_pinned():
    # Changing the algorithm changes every stored fingerprint. This test makes
    # such a change deliberate: update FINGERPRINT_PREFIX and the docs too.
    joined = "\x1f".join(
        [
            "vulnsight.fingerprint.v1",
            "PY-CMD-001",
            "CWE-78",
            "sink:os.system",
            "function:execute",
        ]
    )

    # Independent of short_hash: plain SHA-256, truncated to 32 hex characters.
    assert (
        make_finding().fingerprint
        == hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]
    )
    assert make_finding().fingerprint == "4decba69c4fb5a4d41f44647e8a45f24"


def test_fingerprint_without_a_function_is_deterministic():
    unknown = make_finding(enclosing_function=None)

    assert unknown.fingerprint == make_finding(enclosing_function=None).fingerprint


def test_unknown_function_differs_from_module_level_and_named_functions():
    unknown = make_finding(enclosing_function=None).fingerprint

    assert unknown != make_finding(enclosing_function="<module>").fingerprint
    assert unknown != make_finding(enclosing_function="function-unknown").fingerprint
    assert unknown != make_finding(enclosing_function="unknown").fingerprint


def test_fingerprint_without_a_sink_is_deterministic():
    first = make_credential_finding()
    second = make_credential_finding(location=Location("x/y.py", 90, 0))

    assert first.fingerprint == second.fingerprint


def test_missing_sink_cannot_collide_with_any_real_callee():
    absent = make_credential_finding().fingerprint

    # The encoded form of an absent sink is "no-sink". Real callees always
    # encode as "sink:<callee>", so even a callee spelled like the tag differs.
    for callee in ("no-sink", "<no-sink>-", "sink:", "sink:no-sink", "none", "None"):
        with_sink = make_credential_finding(sink=sink(callee))

        assert with_sink.fingerprint != absent, callee


def test_reserved_no_sink_placeholder_cannot_be_used_as_a_callee():
    with pytest.raises(ValueError, match="reserved"):
        sink("<no-sink>")


def test_sink_and_no_sink_findings_with_the_same_other_fields_differ():
    with_sink = make_credential_finding(sink=sink("os.system"))

    assert with_sink.fingerprint != make_credential_finding().fingerprint


# ---------------------------------------------------------------
# evidence_signature
# ---------------------------------------------------------------


def test_signature_is_none_without_taint_evidence():
    assert make_credential_finding().evidence_signature is None
    assert make_finding(evidence=(), taint_effect=None).evidence_signature is None


def test_signature_is_a_32_character_hash_with_evidence():
    assert len(make_finding().evidence_signature) == 32


def test_signature_contains_no_location():
    base = make_finding()
    moved = make_finding(
        location=Location("elsewhere.py", 900, 0, 900, 20),
        enclosing_function="renamed_function",
        evidence=(make_label(line=700, col=3),),
    )

    assert moved.evidence_signature == base.evidence_signature


def test_signature_depends_on_rule_and_sink():
    base = make_finding().evidence_signature

    assert make_finding(rule_id="PY-CMD-002").evidence_signature != base
    assert make_finding(sink=sink("os.popen")).evidence_signature != base


def test_signature_ignores_the_order_evidence_is_supplied_in():
    first = make_label(origin_id="input()", line=1)
    second = make_label(origin_id="sys.argv", kind=SourceKind.CLI_ARG, line=2)

    forward = make_finding(evidence=(first, second))
    backward = make_finding(evidence=(second, first))

    assert forward.evidence_signature == backward.evidence_signature


def test_signature_does_not_depend_on_where_same_id_origins_sit():
    plain = make_label(origin_id="input()", line=1, steps=(TraceKind.ASSIGN,))
    concat = make_label(origin_id="input()", line=9, steps=(TraceKind.CONCAT,))
    plain_late = replace(plain, origin=replace(plain.origin, line=50))
    concat_early = replace(concat, origin=replace(concat.origin, line=0))

    original = make_finding(evidence=(plain, concat))
    swapped = make_finding(evidence=(plain_late, concat_early))

    assert original.evidence_signature == swapped.evidence_signature


def test_signature_changes_with_the_origin_id():
    base = make_finding().evidence_signature
    other = make_finding(evidence=(make_label(origin_id="input_two()"),))

    assert other.evidence_signature != base


def test_signature_changes_with_the_trace_kind_sequence():
    assign = make_finding(evidence=(make_label(steps=(TraceKind.ASSIGN,)),))
    concat = make_finding(evidence=(make_label(steps=(TraceKind.CONCAT,)),))
    longer = make_finding(
        evidence=(make_label(steps=(TraceKind.ASSIGN, TraceKind.CALL)),)
    )

    assert assign.evidence_signature != concat.evidence_signature
    assert assign.evidence_signature != longer.evidence_signature


def test_signature_keeps_trace_kinds_paired_with_their_origin():
    one = make_label(origin_id="a()", steps=(TraceKind.ASSIGN,))
    two = make_label(origin_id="b()", steps=(TraceKind.CONCAT,))
    one_swapped = make_label(origin_id="a()", steps=(TraceKind.CONCAT,))
    two_swapped = make_label(origin_id="b()", steps=(TraceKind.ASSIGN,))

    first = make_finding(evidence=(one, two))
    second = make_finding(evidence=(one_swapped, two_swapped))

    assert first.evidence_signature != second.evidence_signature


def test_signature_uses_the_sorted_origin_kind_entries():
    one = make_label(origin_id="a()", steps=(TraceKind.ASSIGN,))
    two = make_label(origin_id="b()", steps=(TraceKind.CONCAT,))
    finding = make_finding(evidence=(two, one))

    expected = short_hash(
        "vulnsight.evidence-signature.v1",
        "PY-CMD-001",
        "sink:os.system",
        "a()\x1esource,assign",
        "b()\x1esource,concat",
    )

    assert finding.evidence_signature == expected


def test_duplicate_origin_entries_are_kept_not_merged():
    single = make_finding(evidence=(make_label(origin_id="input()", line=1),))
    double = make_finding(
        evidence=(
            make_label(origin_id="input()", line=1),
            make_label(origin_id="input()", line=7),
        )
    )

    assert single.evidence_signature != double.evidence_signature


# ---------------------------------------------------------------
# finding_id and occurrence
# ---------------------------------------------------------------


def test_finding_id_combines_fingerprint_and_occurrence():
    finding = make_finding(occurrence=3)

    assert finding.finding_id == f"{finding.fingerprint}-3"


def test_occurrence_does_not_change_the_fingerprint():
    assert make_finding(occurrence=5).fingerprint == make_finding().fingerprint


def same_function_findings():
    """Three findings with the same rule, sink and function."""

    return [
        make_finding(location=Location("app/run.py", line, 4, line, 30))
        for line in (30, 10, 20)
    ]


def test_assign_occurrences_numbers_identical_rule_findings_by_position():
    numbered = assign_occurrences(same_function_findings())

    assert [(f.location.line, f.occurrence) for f in numbered] == [
        (10, 0),
        (20, 1),
        (30, 2),
    ]
    assert len({f.finding_id for f in numbered}) == 3
    assert len({f.fingerprint for f in numbered}) == 1


def test_occurrences_do_not_depend_on_input_order():
    findings = same_function_findings()
    expected = assign_occurrences(findings)

    for permutation in itertools.permutations(findings):
        assert assign_occurrences(permutation) == expected


def test_occurrences_do_not_depend_on_file_traversal_order():
    findings = [
        make_finding(location=Location(path, 5, 0, 5, 20))
        for path in ("b/second.py", "a/first.py", "c/third.py")
    ]

    expected = {f.location.file: f.occurrence for f in assign_occurrences(findings)}

    for permutation in itertools.permutations(findings):
        result = assign_occurrences(permutation)

        assert {f.location.file: f.occurrence for f in result} == expected

    assert expected == {"a/first.py": 0, "b/second.py": 1, "c/third.py": 2}


def test_occurrence_order_uses_file_then_line_then_column():
    findings = [
        make_finding(location=Location("a.py", 3, 9, 3, 20)),
        make_finding(location=Location("a.py", 3, 2, 3, 20)),
        make_finding(location=Location("a.py", 1, 0, 1, 20)),
        make_finding(location=Location("0.py", 99, 0, 99, 20)),
    ]

    numbered = assign_occurrences(findings)
    order = {
        (f.location.file, f.location.line, f.location.column): f.occurrence
        for f in numbered
    }

    assert order == {
        ("0.py", 99, 0): 0,
        ("a.py", 1, 0): 1,
        ("a.py", 3, 2): 2,
        ("a.py", 3, 9): 3,
    }


def test_different_functions_are_numbered_separately():
    findings = [
        make_finding(enclosing_function="one"),
        make_finding(enclosing_function="two", location=Location("app/run.py", 40, 4)),
    ]

    numbered = assign_occurrences(findings)

    assert [f.occurrence for f in numbered] == [0, 0]
    assert len({f.finding_id for f in numbered}) == 2


def test_non_taint_findings_without_sinks_are_numbered_too():
    findings = [
        make_credential_finding(location=Location("a.py", line, 0)) for line in (8, 3)
    ]

    numbered = assign_occurrences(findings)

    assert [(f.location.line, f.occurrence) for f in numbered] == [(3, 0), (8, 1)]


def test_assign_occurrences_overwrites_existing_numbers():
    findings = [make_finding(occurrence=7)]

    assert assign_occurrences(findings)[0].occurrence == 0


def test_an_earlier_finding_shifts_ids_but_not_fingerprints():
    original = assign_occurrences(same_function_findings())
    extra = make_finding(location=Location("app/run.py", 5, 4, 5, 30))
    shifted = assign_occurrences([*same_function_findings(), extra])

    assert {f.fingerprint for f in shifted} == {f.fingerprint for f in original}
    assert {f.finding_id for f in shifted} != {f.finding_id for f in original}
    # finding_id is scan-local: the finding at line 10 was 0, now it is 1.
    by_line = {f.location.line: f.occurrence for f in shifted}

    assert by_line[10] == 1


def test_exact_duplicates_are_rejected():
    with pytest.raises(ValueError, match="duplicate finding"):
        assign_occurrences([make_finding(), make_finding()])


def test_assign_occurrences_rejects_non_findings():
    with pytest.raises(ValueError, match="Finding"):
        assign_occurrences([make_finding(), {"rule_id": "x"}])


def test_assign_occurrences_accepts_an_empty_sequence():
    assert assign_occurrences([]) == ()


def test_assign_occurrences_returns_findings_in_canonical_order():
    findings = [
        make_finding(location=Location("b.py", 1, 0)),
        make_finding(location=Location("a.py", 9, 0), enclosing_function="g"),
        make_finding(location=Location("a.py", 2, 0), enclosing_function="f"),
    ]

    result = assign_occurrences(findings)

    assert [(f.location.file, f.location.line) for f in result] == [
        ("a.py", 2),
        ("a.py", 9),
        ("b.py", 1),
    ]
    assert all(isinstance(item, Finding) for item in result)
