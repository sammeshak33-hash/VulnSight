"""Check that Finding v2 fits the real output of the M0.2 taint engine.

The conversion helper below exists only in these tests. The real adapter is
``vulnsight.scanner.adapter`` (M1.2); these tests keep checking the raw engine
output against the model without depending on it.
"""

import textwrap

import pytest

import vulnsight
import vulnsight.models
from vulnsight.findings import (
    ConfidenceLevel,
    Finding,
    Language,
    Location,
    Sink,
    assign_occurrences,
)
from vulnsight.scan_result import ScanResult, ScanStatus
from vulnsight.scanner.command_injection import scan_source
from vulnsight.scanner.specs import ArgSelector, SinkSpec
from vulnsight.scanner.taint_model import (
    MAX_TRACE_STEPS,
    SourceKind,
    TaintEffect,
    TaintValue,
    TraceKind,
)
from vulnsight.scanner.visitor import analyze_source

SYSTEM_SINK = SinkSpec(
    rule_id="TEST-CMD-001",
    cwe="CWE-78",
    names=frozenset({"os.system"}),
    selector=ArgSelector(positions=(0,), keywords=()),
)


def finding_from_hit(hit, file="sample.py"):
    """Test-only conversion of an engine SinkHit into a Finding v2."""

    labels = [label for taint in hit.argument_taints for label in taint.labels]
    combined = TaintValue(tuple(labels))
    effect = combined.effective_for(hit.spec.cwe, {"posix", "windows"})
    node = hit.node

    return Finding(
        rule_id=hit.spec.rule_id,
        cwe=hit.spec.cwe,
        language=Language.PYTHON,
        message=f"Potential issue: tainted data reaches {hit.callee}",
        location=Location(
            file,
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ),
        confidence=ConfidenceLevel.MEDIUM,
        sink=Sink(hit.callee, hit.certainty),
        evidence=tuple(labels),
        taint_effect=effect
        if effect in (TaintEffect.RAW, TaintEffect.PARTIAL)
        else None,
    )


def hits_for(source):
    return analyze_source(textwrap.dedent(source), sink_specs=(SYSTEM_SINK,))


def test_engine_hit_becomes_a_valid_finding():
    hits = hits_for(
        """
        import os

        def run():
            command = input()
            os.system(command)
        """
    )

    assert len(hits) == 1

    finding = finding_from_hit(hits[0])
    origin = finding.evidence[0].origin

    assert finding.sink.callee == "os.system"
    assert finding.taint_effect is TaintEffect.RAW
    assert origin.origin_id == "input()"
    assert origin.kind is SourceKind.INTERACTIVE
    assert finding.evidence[0].trace[0].kind is TraceKind.SOURCE


def test_engine_finding_survives_a_full_json_round_trip():
    hits = hits_for(
        """
        import os
        a = input()
        b = "ls " + a
        os.system(b)
        """
    )
    findings = assign_occurrences([finding_from_hit(hit) for hit in hits])
    result = ScanResult(status=ScanStatus.COMPLETE, findings=findings)

    assert ScanResult.from_json(result.to_json()) == result


def test_partial_sanitizer_information_is_carried_from_the_engine():
    hits = hits_for(
        """
        import os, shlex
        command = shlex.quote(input())
        os.system(command)
        """
    )

    finding = finding_from_hit(hits[0])
    neutralizations = finding.evidence[0].neutralizations

    assert finding.taint_effect is TaintEffect.PARTIAL
    assert {item.via for item in neutralizations} == {"shlex.quote"}
    assert Finding.from_dict(finding.to_dict()) == finding


def test_long_engine_traces_with_an_elided_marker_round_trip():
    chain = "\n".join(f'c{index + 1} = c{index} + "x"' for index in range(20))
    hits = hits_for(f"import os\nc0 = input()\n{chain}\nos.system(c20)\n")

    finding = finding_from_hit(hits[0])
    kinds = [step.kind for step in finding.evidence[0].trace]

    assert len(kinds) == MAX_TRACE_STEPS
    assert TraceKind.ELIDED in kinds
    assert Finding.from_dict(finding.to_dict()) == finding


def test_two_tainted_arguments_give_evidence_for_each_origin():
    spec = SinkSpec(
        rule_id="TEST-TWO-001",
        cwe="CWE-78",
        names=frozenset({"run"}),
        selector=ArgSelector(positions=(0, 1), keywords=()),
    )
    hits = analyze_source("a = input()\nb = input()\nrun(a, b)\n", sink_specs=(spec,))

    finding = finding_from_hit(hits[0])

    assert len(finding.evidence) == 2
    assert finding.evidence_signature is not None
    assert Finding.from_dict(finding.to_dict()) == finding


def test_equal_origins_from_two_arguments_still_round_trip():
    spec = SinkSpec(
        rule_id="TEST-TWO-001",
        cwe="CWE-78",
        names=frozenset({"run"}),
        selector=ArgSelector(positions=(0, 1), keywords=()),
    )
    hits = analyze_source("a = input()\nrun(a, a)\n", sink_specs=(spec,))

    finding = finding_from_hit(hits[0])

    assert Finding.from_dict(finding.to_dict()) == finding


# ---------------------------------------------------------------
# Compatibility with existing (v1) callers
# ---------------------------------------------------------------


def test_the_detector_now_produces_finding_v2():
    findings = scan_source('import os\nos.system(input("x"))\n')

    assert len(findings) == 1
    assert type(findings[0]) is Finding
    assert not isinstance(findings[0], vulnsight.models.Finding)


def test_package_root_exports_finding_v2():
    assert vulnsight.Finding is Finding
    assert vulnsight.Finding is not vulnsight.models.Finding


def test_legacy_finding_is_unchanged():
    legacy = vulnsight.models.Finding(
        function="os.system",
        line=5,
        cwe="CWE-78",
        severity="Review required",
        message="m",
    )

    assert legacy["function"] == "os.system"
    assert legacy.to_dict()["cwe"] == "CWE-78"
    assert legacy.get("unknown", "default") == "default"
    assert legacy.confidence == "medium"


def test_v2_answers_the_legacy_keys_with_the_values_the_old_detector_gave():
    # Values recorded from the legacy detector for this input before it was
    # replaced. ``source`` is the one deliberate difference: v1 stored the
    # constant label "Untrusted input", v2 reports the real origin ids.
    legacy_values = {
        "function": "os.system",
        "line": 2,
        "cwe": "CWE-78",
        "severity": "Review required",
        "rule_id": "PY-CMD-001",
        "confidence": "medium",
        "sink": "os.system",
    }
    new = scan_source('import os\nos.system(input("x"))\n')[0]

    for key, value in legacy_values.items():
        assert new[key] == value, key

    assert new["source"] == "input()"


@pytest.mark.parametrize("key", ["function", "line", "cwe", "severity", "sink"])
def test_v2_get_matches_getitem_for_legacy_keys(key):
    hits = hits_for("import os\nos.system(input())\n")
    finding = finding_from_hit(hits[0])

    assert finding.get(key) == finding[key]
