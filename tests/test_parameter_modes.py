"""M1.3: parameter modes.

Strict mode (the default) keeps parameters clean. Recall mode taints the
parameters of module-level functions and class methods with
``SourceKind.PARAMETER`` and gives parameter-only findings low confidence.
"""

import ast

import pytest

from tests.differential_corpus import CASES
from vulnsight.findings import ConfidenceLevel
from vulnsight.scan_result import ScanMetadata, ScanResult, ScanStatus
from vulnsight.scanner.adapter import cap_confidence, parameter_only
from vulnsight.scanner.command_injection import SINK_SPECS, detect
from vulnsight.scanner.policy import (
    ParameterMode,
    TaintPolicy,
    create_default_policy,
)
from vulnsight.scanner.taint_model import SourceKind, TaintEffect
from vulnsight.scanner.visitor import TaintVisitor

STRICT = create_default_policy(ParameterMode.STRICT)
RECALL = create_default_policy(ParameterMode.RECALL)


def scan(source, policy=RECALL):
    return detect(ast.parse(source), policy=policy)


def lines(findings):
    return [finding.location.line for finding in findings]


def origins(finding):
    return sorted(label.origin.origin_id for label in finding.evidence)


# ---------------------------------------------------------------
# Mode and policy
# ---------------------------------------------------------------


def test_parameter_mode_values_are_the_documented_strings():
    assert ParameterMode.STRICT.value == "strict"
    assert ParameterMode.RECALL.value == "recall"
    assert {mode.value for mode in ParameterMode} == {"strict", "recall"}


def test_strict_is_the_default_everywhere():
    assert create_default_policy().parameter_mode is ParameterMode.STRICT
    assert TaintPolicy((), ()).parameter_mode is ParameterMode.STRICT
    assert TaintVisitor().policy.parameter_mode is ParameterMode.STRICT


def test_policy_rejects_a_plain_string_mode():
    with pytest.raises(ValueError, match="parameter_mode"):
        TaintPolicy((), (), parameter_mode="recall")


def test_default_policy_sources_do_not_depend_on_the_mode():
    assert STRICT.sources == RECALL.sources
    assert STRICT.sanitizers == RECALL.sanitizers


def test_source_kind_has_a_parameter_member():
    assert SourceKind.PARAMETER.value == "parameter"


# ---------------------------------------------------------------
# Strict mode is unchanged
# ---------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_explicit_strict_mode_matches_every_corpus_verdict(case):
    findings = scan(case.source, STRICT)

    verdict = tuple(
        (
            f.location.line,
            f.sink.callee,
            f.taint_effect.value,
            f.confidence.value,
        )
        for f in findings
    )

    assert verdict == case.new


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_explicit_strict_equals_default_policy(case):
    tree = ast.parse(case.source)

    assert detect(tree, policy=STRICT) == detect(tree)


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_recall_mode_never_loses_a_strict_finding(case):
    strict = {(f.location.line, f.sink.callee) for f in scan(case.source, STRICT)}
    recall = {(f.location.line, f.sink.callee) for f in scan(case.source, RECALL)}

    assert strict <= recall


def test_strict_mode_leaves_every_parameter_clean():
    source = """
import os

def f(a, /, b, *, c):
    os.system(a)
    os.system(b)
    os.system(c)

class K:
    def m(self, x):
        os.system(x)
"""

    assert scan(source, STRICT) == []


# ---------------------------------------------------------------
# Recall mode: which parameters are sources
# ---------------------------------------------------------------


def test_module_function_parameter_is_a_source():
    findings = scan("import os\ndef run(cmd):\n    os.system(cmd)\n")

    assert len(findings) == 1

    finding = findings[0]
    label = finding.evidence[0]

    assert finding.taint_effect is TaintEffect.RAW
    assert label.origin.kind is SourceKind.PARAMETER
    assert label.origin.origin_id == "param:run.cmd"
    assert (label.origin.line, label.origin.col) == (2, 8)
    assert finding.enclosing_function == "run"


def test_async_function_parameter_is_a_source():
    findings = scan("import os\nasync def run(cmd):\n    os.system(cmd)\n")

    assert origins(findings[0]) == ["param:run.cmd"]


def test_positional_only_regular_and_keyword_only_parameters_are_sources():
    source = """
import os

def f(a, /, b, *, c):
    os.system(a)
    os.system(b)
    os.system(c)
"""
    findings = scan(source)

    assert lines(findings) == [5, 6, 7]
    assert [origins(f)[0] for f in findings] == [
        "param:f.a",
        "param:f.b",
        "param:f.c",
    ]


def test_star_args_and_kwargs_are_excluded():
    source = """
import os

def f(*args, **kwargs):
    os.system(args)
    os.system(kwargs)
    os.system(args[0])
    os.system(kwargs["x"])
"""

    assert scan(source) == []


def test_star_args_exclusion_does_not_hide_the_other_parameters():
    source = """
import os

def f(a, *args, b, **kwargs):
    os.system(a)
    os.system(b)
    os.system(args)
"""

    assert lines(scan(source)) == [5, 6]


def test_private_function_is_included():
    source = "import os\ndef _helper(cmd):\n    os.system(cmd)\n"

    assert origins(scan(source)[0]) == ["param:_helper.cmd"]


def test_dunder_method_is_included():
    source = """
import os

class K:
    def __init__(self, cmd):
        os.system(cmd)
"""

    assert origins(scan(source)[0]) == ["param:K.__init__.cmd"]


def test_function_defined_under_a_module_level_block_is_included():
    source = """
import os

if True:
    def run(cmd):
        os.system(cmd)
"""

    assert lines(scan(source)) == [6]


# ---------------------------------------------------------------
# Methods: receiver handling
# ---------------------------------------------------------------


def test_normal_method_skips_self_but_taints_the_rest():
    source = """
import os

class K:
    def run(self, cmd):
        os.system(self)
        os.system(cmd)
"""
    findings = scan(source)

    assert lines(findings) == [7]
    assert origins(findings[0]) == ["param:K.run.cmd"]


def test_receiver_is_skipped_whatever_it_is_called():
    source = """
import os

class K:
    def run(this, cmd):
        os.system(this)
"""

    assert scan(source) == []


def test_class_method_skips_cls_but_taints_the_rest():
    source = """
import os

class K:
    @classmethod
    def build(cls, cmd):
        os.system(cls)
        os.system(cmd)
"""
    findings = scan(source)

    assert lines(findings) == [8]
    assert origins(findings[0]) == ["param:K.build.cmd"]


def test_static_method_does_not_skip_its_first_parameter():
    source = """
import os

class K:
    @staticmethod
    def build(cmd, other):
        os.system(cmd)
        os.system(other)
"""
    findings = scan(source)

    assert lines(findings) == [7, 8]
    assert origins(findings[0]) == ["param:K.build.cmd"]


def test_normal_class_and_static_methods_side_by_side():
    source = """
import os

class K:
    def a(self, x):
        os.system(self)

    @classmethod
    def b(cls, x):
        os.system(cls)

    @staticmethod
    def c(x):
        os.system(x)
"""

    assert lines(scan(source)) == [14]


def test_method_without_parameters_does_not_fail():
    source = "class K:\n    def m():\n        pass\n"

    assert scan(source) == []


def test_posonly_receiver_is_skipped():
    source = """
import os

class K:
    def m(self, /, x):
        os.system(self)
        os.system(x)
"""

    assert lines(scan(source)) == [7]


def test_nested_class_method_is_included():
    source = """
import os

class Outer:
    class Inner:
        def run(self, cmd):
            os.system(cmd)
"""
    findings = scan(source)

    assert origins(findings[0]) == ["param:Outer.Inner.run.cmd"]


# ---------------------------------------------------------------
# Recall mode: scopes that are not sources
# ---------------------------------------------------------------


def test_nested_function_parameters_are_clean():
    source = """
import os

def outer():
    def inner(cmd):
        os.system(cmd)
    inner("x")
"""

    assert scan(source) == []


def test_nested_function_inside_a_method_is_clean():
    source = """
import os

class K:
    def run(self):
        def inner(cmd):
            os.system(cmd)
"""

    assert scan(source) == []


def test_function_nested_two_levels_deep_is_clean():
    source = """
import os

def a():
    def b():
        def c(cmd):
            os.system(cmd)
"""

    assert scan(source) == []


def test_lambda_parameters_are_clean():
    source = """
import os

run = lambda cmd: os.system(cmd)

def f():
    return lambda cmd: os.system(cmd)
"""

    assert scan(source) == []


def test_class_defined_inside_a_function_is_clean():
    source = """
import os

def factory():
    class Inner:
        def run(self, cmd):
            os.system(cmd)
        @staticmethod
        def s(cmd):
            os.system(cmd)
"""

    assert scan(source) == []


def test_enclosing_function_parameter_still_taints_a_nested_closure():
    source = """
import os

def outer(cmd):
    def inner():
        os.system(cmd)
    inner()
"""
    findings = scan(source)

    assert lines(findings) == [6]
    assert origins(findings[0]) == ["param:outer.cmd"]
    assert findings[0].enclosing_function == "outer.inner"


def test_outer_function_is_still_analyzed_when_inner_is_skipped():
    source = """
import os

def outer(a):
    def inner(b):
        os.system(b)
    os.system(a)
"""

    assert lines(scan(source)) == [7]


def test_default_values_and_decorators_do_not_make_taint():
    source = """
import os

def f(a="x"):
    os.system("ls")
"""

    assert scan(source) == []


# ---------------------------------------------------------------
# Flow: propagation, reassignment, sanitizers
# ---------------------------------------------------------------


def test_parameter_taint_propagates_through_concatenation_and_methods():
    source = """
import os

def f(a, b, c):
    os.system("x " + a)
    os.system(f"x {b}")
    os.system(c.strip())
"""

    assert lines(scan(source)) == [5, 6, 7]


def test_reassigning_a_parameter_to_a_constant_clears_it():
    source = """
import os

def f(cmd):
    cmd = "ls"
    os.system(cmd)
"""

    assert scan(source) == []


def test_reassigning_a_parameter_from_itself_keeps_it():
    source = """
import os

def f(cmd):
    cmd = cmd + " -l"
    os.system(cmd)
"""

    assert lines(scan(source)) == [6]


def test_reassigning_in_one_branch_keeps_the_taint():
    source = """
import os

def f(cmd, flag):
    if flag:
        cmd = "ls"
    os.system(cmd)
"""

    assert lines(scan(source)) == [7]


def test_int_sanitizer_removes_parameter_taint():
    source = """
import os

def f(n):
    os.system("sleep " + str(int(n)))
    os.system(int(n))
"""

    assert scan(source) == []


def test_shlex_quote_leaves_a_partial_low_finding():
    source = """
import os, shlex

def f(cmd):
    os.system(shlex.quote(cmd))
"""
    findings = scan(source)

    assert len(findings) == 1
    assert findings[0].taint_effect is TaintEffect.PARTIAL
    assert findings[0].confidence is ConfidenceLevel.LOW


def test_a_local_that_shadows_a_parameter_name_in_another_function_is_clean():
    source = """
import os

def f(cmd):
    pass

def g():
    cmd = "ls"
    os.system(cmd)
"""

    assert scan(source) == []


def test_get_and_copy_do_not_propagate_from_a_parameter():
    source = """
import os

def f(options):
    os.system(options.get("x"))
    os.system(options.copy())
"""

    assert scan(source) == []


def test_shell_guard_still_applies_to_parameter_flows():
    source = """
import subprocess

def f(cmd):
    subprocess.run(cmd)
    subprocess.run(cmd, shell=True)
"""

    assert lines(scan(source)) == [6]


# ---------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------


def test_parameter_only_raw_finding_is_low_confidence():
    finding = scan("import os\ndef f(c):\n    os.system(c)\n")[0]

    assert finding.taint_effect is TaintEffect.RAW
    assert finding.confidence is ConfidenceLevel.LOW


def test_the_same_flow_from_a_real_source_keeps_medium_confidence():
    finding = scan("import os\ndef f():\n    os.system(input())\n")[0]

    assert finding.confidence is ConfidenceLevel.MEDIUM


def test_mixed_parameter_and_real_source_keeps_effect_based_confidence():
    source = """
import os

def f(a):
    os.system(a + input())
"""
    finding = scan(source)[0]

    assert finding.taint_effect is TaintEffect.RAW
    assert finding.confidence is ConfidenceLevel.MEDIUM
    assert {label.origin.kind for label in finding.evidence} == {
        SourceKind.PARAMETER,
        SourceKind.INTERACTIVE,
    }


def test_mixed_evidence_from_two_variables_keeps_medium_confidence():
    source = """
import os

def f(a):
    b = input()
    os.system(a + b)
"""

    assert scan(source)[0].confidence is ConfidenceLevel.MEDIUM


def test_environment_source_with_parameter_keeps_medium_confidence():
    source = """
import os

def f(a):
    os.system(a + os.environ["X"])
"""

    assert scan(source)[0].confidence is ConfidenceLevel.MEDIUM


def test_two_parameters_are_still_parameter_only():
    source = "import os\ndef f(a, b):\n    os.system(a + b)\n"
    finding = scan(source)[0]

    assert origins(finding) == ["param:f.a", "param:f.b"]
    assert finding.confidence is ConfidenceLevel.LOW


def test_message_and_other_fields_are_normal_for_parameter_findings():
    finding = scan("import os\ndef f(c):\n    os.system(c)\n")[0]

    assert finding.rule_id == "PY-CMD-001"
    assert finding.cwe == "CWE-78"
    assert finding.message.startswith("Potential command injection")
    assert finding.sink.callee == "os.system"


def test_parameter_only_and_cap_helpers():
    assert parameter_only(()) is False
    assert cap_confidence(ConfidenceLevel.HIGH, ConfidenceLevel.LOW) is (
        ConfidenceLevel.LOW
    )
    assert cap_confidence(ConfidenceLevel.LOW, ConfidenceLevel.HIGH) is (
        ConfidenceLevel.LOW
    )
    assert cap_confidence(ConfidenceLevel.MEDIUM, ConfidenceLevel.MEDIUM) is (
        ConfidenceLevel.MEDIUM
    )


# ---------------------------------------------------------------
# M1.2 deduplication still picks the strongest effect
# ---------------------------------------------------------------


def test_strongest_effect_still_wins_when_hits_repeat():
    from vulnsight.scanner.adapter import findings_from_hits
    from vulnsight.scanner.command_injection import (
        CONFIDENCE_BY_EFFECT,
        describe,
    )

    source = "import os\ndef f(c):\n    os.system(c)\n"
    tree = ast.parse(source)
    hits = TaintVisitor(policy=RECALL, sink_specs=SINK_SPECS).analyze(tree)

    findings = findings_from_hits(
        hits + hits,
        tree,
        describe=describe,
        confidence_by_effect=CONFIDENCE_BY_EFFECT,
    )

    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.LOW


def test_a_parameter_hit_does_not_hide_a_real_source_hit_on_one_call():
    # RAW from a real source and PARTIAL from a parameter on one call: the
    # strongest effect decides, and its evidence is what sets the confidence.
    source = """
import os, shlex

def f(a):
    os.system(input() + shlex.quote(a))
"""
    finding = scan(source)[0]

    assert finding.taint_effect is TaintEffect.RAW
    assert finding.confidence is ConfidenceLevel.MEDIUM


def test_parameter_raw_with_real_source_partial_keeps_medium_confidence():
    source = """
import os, shlex

def f(a):
    os.system(a + shlex.quote(input()))
"""
    finding = scan(source)[0]

    assert finding.taint_effect is TaintEffect.RAW
    assert {label.origin.kind for label in finding.evidence} == {
        SourceKind.PARAMETER,
        SourceKind.INTERACTIVE,
    }


# ---------------------------------------------------------------
# Output order, determinism and JSON
# ---------------------------------------------------------------


def test_recall_output_is_deterministic():
    source = """
import os

def a(x):
    os.system(x)

class K:
    def b(self, y):
        os.system(y)
"""

    assert [f.to_dict() for f in scan(source)] == [f.to_dict() for f in scan(source)]
    assert lines(scan(source)) == [5, 9]


def test_parameter_evidence_round_trips_through_json_under_schema_2_1():
    source = """
import os

def f(a):
    os.system(a)
    os.system(a + input())
"""
    findings = scan(source)
    result = ScanResult(
        status=ScanStatus.COMPLETE,
        findings=findings,
        metadata=ScanMetadata.with_settings({"parameter_mode": "recall"}),
    )

    text = result.to_json()
    loaded = ScanResult.from_json(text)

    assert '"schema_version": "2.1"' in text
    assert '"kind": "parameter"' in text
    assert '"origin_id": "param:f.a"' in text
    assert loaded == result
    assert loaded.to_json() == text
    assert dict(loaded.metadata.settings) == {"parameter_mode": "recall"}

    kinds = [label.origin.kind for label in loaded.findings[0].evidence]

    assert kinds == [SourceKind.PARAMETER]


def test_evidence_signature_tells_parameters_apart():
    source = "import os\ndef f(a, b):\n    os.system(a)\n    os.system(b)\n"
    first, second = scan(source)

    assert first.evidence_signature != second.evidence_signature
