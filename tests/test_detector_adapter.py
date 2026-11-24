"""Tests for the CWE-78 detector and the reusable sink-hit adapter."""

import ast
import dataclasses
import textwrap

import pytest

import vulnsight
import vulnsight.models
from vulnsight.findings import ConfidenceLevel, Finding, Language
from vulnsight.rules import create_default_registry
from vulnsight.scan_result import ScanResult, ScanStatus
from vulnsight.scanner import command_injection
from vulnsight.scanner.adapter import (
    build_parent_map,
    enclosing_function_name,
    findings_from_hits,
    taint_effect_of,
)
from vulnsight.scanner.command_injection import (
    SINK_SPECS,
    detect,
    scan_source,
    shell_guard,
)
from vulnsight.scanner.policy import TaintPolicy, create_default_policy
from vulnsight.scanner.scope import ResolutionCertainty
from vulnsight.scanner.specs import GuardResult, SinkSpec, SourceSpec
from vulnsight.scanner.taint_model import SourceKind, TaintEffect
from vulnsight.scanner.visitor import TaintVisitor


def code(source):
    return textwrap.dedent(source).lstrip("\n")


# ---------------------------------------------------------------
# Enclosing-function naming: checked against the engine itself
# ---------------------------------------------------------------

# Each case is (source, expected enclosing_function, expected engine scope
# kind). The expectations were read from TaintVisitor (_qualname, visit_Lambda,
# visit_ClassDef and _analyze_deferred_function), and the oracle test below
# compares every case with what the engine really uses.

SCOPE_CASES = [
    pytest.param(
        "import os\nos.system(input())\n",
        "<module>",
        "module",
        id="module-level",
    ),
    pytest.param(
        "import os\ndef f():\n    os.system(input())\n",
        "f",
        "function",
        id="function",
    ),
    pytest.param(
        "import os\nasync def f():\n    os.system(input())\n",
        "f",
        "function",
        id="async-function",
    ),
    pytest.param(
        "import os\nclass C:\n    def m(self):\n        os.system(input())\n",
        "C.m",
        "method",
        id="method",
    ),
    pytest.param(
        "import os\ndef f():\n    def g():\n        os.system(input())\n",
        "f.g",
        "function",
        id="nested-function",
    ),
    pytest.param(
        "import os\ndef f():\n    def g():\n        def h():\n"
        "            os.system(input())\n",
        "f.g.h",
        "function",
        id="doubly-nested-function",
    ),
    pytest.param(
        "import os\ndef f():\n    class C:\n        def m(self):\n"
        "            os.system(input())\n",
        "f.C.m",
        "method",
        id="class-inside-function",
    ),
    pytest.param(
        "import os\nclass Outer:\n    class Inner:\n        def m(self):\n"
        "            os.system(input())\n",
        "Outer.Inner.m",
        "method",
        id="nested-class-method",
    ),
    pytest.param(
        "import os\nclass C:\n    os.system(input())\n",
        "C",
        "class",
        id="class-body-statement",
    ),
    pytest.param(
        "import os\nclass C:\n    def m(self):\n        def helper():\n"
        "            os.system(input())\n",
        "C.m.helper",
        "function",
        id="function-inside-method",
    ),
    pytest.param(
        "import os\nclass C:\n    if True:\n        def m(self):\n"
        "            os.system(input())\n",
        "C.m",
        "method",
        id="method-defined-under-if",
    ),
    pytest.param(
        "import os\ndef f():\n    try:\n        for x in range(2):\n"
        "            with open('a') as h:\n                os.system(input())\n"
        "    except Exception:\n        pass\n",
        "f",
        "function",
        id="inside-try-for-with",
    ),
    pytest.param(
        "import os\ndef f():\n    return [os.system(input()) for x in range(2)]\n",
        "f",
        "function",
        id="comprehension-in-function",
    ),
    pytest.param(
        "import os\nrun = lambda: os.system(input())\n",
        "<lambda@2>",
        "lambda",
        id="module-lambda",
    ),
    pytest.param(
        "import os\ndef f():\n    run = lambda: os.system(input())\n",
        "<lambda@3>",
        "lambda",
        id="lambda-in-function-has-no-prefix",
    ),
    pytest.param(
        "import os\nclass C:\n    def m(self):\n"
        "        run = lambda: os.system(input())\n",
        "<lambda@4>",
        "lambda",
        id="lambda-in-method-has-no-prefix",
    ),
    pytest.param(
        "import os\nclass C:\n    f = lambda self: os.system(input())\n",
        "<lambda@3>",
        "lambda",
        id="lambda-in-class-body",
    ),
    pytest.param(
        "import os\nrun = lambda a: (lambda b: os.system(input()))\n",
        "<lambda@2>",
        "lambda",
        id="nested-lambda-takes-the-inner-name",
    ),
    pytest.param(
        "import os\n@decorate(os.system(input()))\ndef f():\n    pass\n",
        "<module>",
        "module",
        id="decorator-runs-in-the-outer-scope",
    ),
    pytest.param(
        "import os\nclass C:\n    @decorate(os.system(input()))\n"
        "    def m(self):\n        pass\n",
        "C",
        "class",
        id="method-decorator-runs-in-the-class-body",
    ),
    pytest.param(
        "import os\ndef f(a=os.system(input())):\n    pass\n",
        "<module>",
        "module",
        id="default-value-runs-in-the-outer-scope",
    ),
    pytest.param(
        "import os\ndef f():\n    def g(a=os.system(input())):\n        pass\n",
        "f",
        "function",
        id="nested-default-runs-in-the-enclosing-function",
    ),
    pytest.param(
        "import os\ndef f(*, a=os.system(input())):\n    pass\n",
        "<module>",
        "module",
        id="keyword-only-default",
    ),
    pytest.param(
        "import os\ndef f(a: os.system(input())):\n    pass\n",
        "<module>",
        "module",
        id="argument-annotation",
    ),
    pytest.param(
        "import os\ndef f() -> os.system(input()):\n    pass\n",
        "<module>",
        "module",
        id="return-annotation",
    ),
    pytest.param(
        "import os\nclass C(os.system(input())):\n    pass\n",
        "<module>",
        "module",
        id="class-base",
    ),
    pytest.param(
        "import os\nclass C(metaclass=os.system(input())):\n    pass\n",
        "<module>",
        "module",
        id="class-keyword",
    ),
    pytest.param(
        "import os\ng = lambda a=os.system(input()): a\n",
        "<module>",
        "module",
        id="lambda-default-runs-in-the-outer-scope",
    ),
]


@pytest.mark.parametrize(("source", "expected", "kind"), SCOPE_CASES)
def test_enclosing_function_follows_the_engine_naming(source, expected, kind):
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].enclosing_function == expected


@pytest.mark.parametrize(("source", "expected", "kind"), SCOPE_CASES)
def test_enclosing_function_equals_the_names_the_engine_uses(
    monkeypatch, source, expected, kind
):
    """Oracle: record what the engine itself uses when it reaches each call.

    This reads the engine's private ``_function_qualname``. The test exists to
    fail loudly if the engine's naming ever changes.
    """

    seen = {}
    original = TaintVisitor.visit_Call

    def recording(self, node):
        seen.setdefault(
            (node.lineno, node.col_offset),
            (self._function_qualname, self.scope_kind),
        )

        return original(self, node)

    monkeypatch.setattr(TaintVisitor, "visit_Call", recording)

    findings = scan_source(source)
    finding = findings[0]
    engine_name, engine_kind = seen[(finding.location.line, finding.location.column)]

    assert finding.enclosing_function == engine_name == expected
    assert engine_kind == kind


def test_enclosing_function_name_works_on_a_bare_tree():
    tree = ast.parse("class C:\n    def m(self):\n        run(1)\n")
    parents = build_parent_map(tree)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))

    assert enclosing_function_name(call, parents) == "C.m"


# ---------------------------------------------------------------
# The shell rule
# ---------------------------------------------------------------


def guard_result(call_source):
    node = ast.parse(call_source, mode="eval").body

    return shell_guard(node).result


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("run(c, shell=True)", GuardResult.APPLIES),
        ("run(c, shell=False)", GuardResult.NOT_APPLICABLE),
        ("run(c, shell=None)", GuardResult.NOT_APPLICABLE),
        ("run(c, shell=1)", GuardResult.NOT_APPLICABLE),
        ("run(c)", GuardResult.NOT_APPLICABLE),
        ("run(c, cwd=d)", GuardResult.NOT_APPLICABLE),
        ("run(c, shell=flag)", GuardResult.UNKNOWN),
        ("run(c, shell=not flag)", GuardResult.UNKNOWN),
        ("run(c, **options)", GuardResult.UNKNOWN),
        ("run(c, shell=True, **options)", GuardResult.APPLIES),
        ("run(c, shell=False, **options)", GuardResult.NOT_APPLICABLE),
    ],
)
def test_shell_guard_decisions(call, expected):
    assert guard_result(call) == expected


def subprocess_source(arguments):
    return f"import subprocess\nsubprocess.run(input(), {arguments})\n"


@pytest.mark.parametrize("arguments", ["shell=True", "shell=True, cwd='.'"])
def test_shell_true_is_reported(arguments):
    assert len(scan_source(subprocess_source(arguments))) == 1


@pytest.mark.parametrize(
    "arguments",
    ["shell=False", "shell=None", "shell=0", "cwd='.'", "shell=flag", "**options"],
)
def test_other_shell_values_are_not_reported_by_default(arguments):
    assert scan_source(subprocess_source(arguments)) == []


@pytest.mark.parametrize("arguments", ["shell=flag", "**options"])
def test_unknown_shell_is_reported_when_the_constant_is_switched_on(
    monkeypatch, arguments
):
    monkeypatch.setattr(command_injection, "REPORT_UNKNOWN_SHELL", True)

    assert len(scan_source(subprocess_source(arguments))) == 1


def test_known_false_shell_stays_suppressed_when_unknown_is_reported(monkeypatch):
    monkeypatch.setattr(command_injection, "REPORT_UNKNOWN_SHELL", True)

    assert scan_source(subprocess_source("shell=False")) == []


def test_unknown_shell_suppression_is_off_the_default_constant():
    assert command_injection.REPORT_UNKNOWN_SHELL is False


def test_only_the_command_argument_counts():
    source = code(
        """
        import subprocess
        subprocess.run("dir", shell=True, cwd=input())
        """
    )

    assert scan_source(source) == []


def test_command_can_be_passed_by_keyword():
    source = code(
        """
        import subprocess
        subprocess.run(args=input(), shell=True)
        """
    )

    assert len(scan_source(source)) == 1


@pytest.mark.parametrize(
    "callee",
    [
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    ],
)
def test_every_subprocess_sink_needs_shell_true(callee):
    source = f"import subprocess\n{callee}(input(), shell=True)\n"

    assert [finding.sink.callee for finding in scan_source(source)] == [callee]
    assert scan_source(source.replace(", shell=True", "")) == []


@pytest.mark.parametrize("callee", ["os.system", "os.popen"])
def test_every_os_sink_is_reported_without_a_guard(callee):
    source = f"import os\n{callee}(input())\n"

    assert [finding.sink.callee for finding in scan_source(source)] == [callee]


def test_sink_specs_declare_exactly_the_documented_sinks():
    names = {name for spec in SINK_SPECS for name in spec.names}

    assert names == command_injection.OS_SINKS | command_injection.SUBPROCESS_SINKS
    assert all(spec.rule_id == "PY-CMD-001" for spec in SINK_SPECS)
    assert all(spec.cwe == "CWE-78" for spec in SINK_SPECS)


# ---------------------------------------------------------------
# Taint effect, confidence and message
# ---------------------------------------------------------------


def test_raw_taint_is_reported_with_medium_confidence():
    finding = scan_source("import os\nos.system(input())\n")[0]

    assert finding.taint_effect is TaintEffect.RAW
    assert finding.confidence is ConfidenceLevel.MEDIUM
    assert finding.message == (
        "Potential command injection: tainted data reaches os.system"
    )


def test_shlex_quote_is_partial_low_confidence_and_documents_the_platform():
    finding = scan_source(
        "import os, shlex\nos.system(shlex.quote(input()))\n",
    )[0]

    assert finding.taint_effect is TaintEffect.PARTIAL
    assert finding.confidence is ConfidenceLevel.LOW
    assert "POSIX-specific" in finding.message
    assert "not safe Windows command escaping" in finding.message
    assert {item.via for item in finding.evidence[0].neutralizations} == {"shlex.quote"}


@pytest.mark.parametrize("sanitizer", ["int", "float", "bool", "len"])
def test_neutralizing_sanitizers_produce_no_finding(sanitizer):
    source = f"import os\nos.system('echo ' + str({sanitizer}(input())))\n"

    assert scan_source(source) == []


def test_raw_wins_over_partial_when_one_argument_is_unsanitized():
    source = code(
        """
        import os, shlex
        a = shlex.quote(input())
        b = input()
        os.system(a + b)
        """
    )
    finding = scan_source(source)[0]

    assert finding.taint_effect is TaintEffect.RAW
    assert finding.confidence is ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------
# Finding contents
# ---------------------------------------------------------------


def test_finding_fields_are_populated_from_the_hit():
    source = code(
        """
        import os

        def run():
            command = input("cmd: ")
            os.system(command)
        """
    )
    finding = scan_source(source)[0]

    assert isinstance(finding, Finding)
    assert finding.rule_id == "PY-CMD-001"
    assert finding.cwe == "CWE-78"
    assert finding.language is Language.PYTHON
    assert finding.enclosing_function == "run"
    assert finding.sink.callee == "os.system"
    assert finding.sink.certainty is ResolutionCertainty.DEFINITE
    assert finding.location.file is None
    assert (finding.location.line, finding.location.column) == (5, 4)
    assert (finding.location.end_line, finding.location.end_column) == (5, 22)
    assert [label.origin.origin_id for label in finding.evidence] == ["input()"]
    assert finding.evidence[0].origin.kind is SourceKind.INTERACTIVE
    assert finding.severity is None
    assert finding.verification is None
    assert finding.structure_hash is None
    assert finding.occurrence == 0


def test_alias_is_reported_with_the_resolved_callee():
    source = "from os import system as execute\nexecute(input())\n"

    assert scan_source(source)[0].sink.callee == "os.system"


def test_all_tainted_origins_are_kept_as_evidence():
    source = code(
        """
        import os, sys
        os.system(input() + sys.argv[1])
        """
    )
    origins = {label.origin.origin_id for label in scan_source(source)[0].evidence}

    assert origins == {"input()", "sys.argv"}


def test_file_path_is_recorded_and_normalized():
    tree = ast.parse("import os\nos.system(input())\n")

    finding = detect(tree, file="pkg\\mod.py")[0]

    assert finding.location.file == "pkg/mod.py"


def test_policy_can_be_replaced():
    default = create_default_policy()
    policy = TaintPolicy(
        sources=default.sources
        + (
            SourceSpec(
                names=frozenset({"fetch"}),
                kind=SourceKind.NETWORK,
                origin_id="fetch()",
            ),
        ),
        sanitizers=default.sanitizers,
    )
    tree = ast.parse("import os\nos.system(fetch())\n")

    assert detect(tree) == []
    assert len(detect(tree, policy=policy)) == 1


# ---------------------------------------------------------------
# Result shape, ordering and compatibility
# ---------------------------------------------------------------


def test_scan_source_returns_a_list_of_finding_v2():
    clean = scan_source("print('hi')\n")
    flagged = scan_source("import os\nos.system(input())\n")

    assert clean == []
    assert type(clean) is list
    assert type(flagged) is list
    assert all(type(item) is Finding for item in flagged)


def test_syntax_error_still_raises_value_error_with_the_old_message():
    with pytest.raises(ValueError, match=r"^Invalid Python source code: "):
        scan_source("if True print('hello')")


def test_findings_are_ordered_by_position():
    source = code(
        """
        import os
        def later():
            os.system(input())
        os.system(input())
        os.system(input()); os.system(input())
        """
    )
    findings = scan_source(source)
    positions = [(item.location.line, item.location.column) for item in findings]

    assert positions == sorted(positions)
    assert len(findings) == 4


def test_result_is_deterministic():
    source = code(
        """
        import os
        def a():
            os.system(input())
        def b():
            os.system(input())
        os.system(input())
        """
    )

    first = scan_source(source)
    second = scan_source(source)

    assert first == second
    assert [item.finding_id for item in first] == [item.finding_id for item in second]


def test_same_fingerprint_findings_get_distinct_occurrences():
    source = code(
        """
        import os
        os.system(input())
        os.system(input())
        """
    )
    findings = scan_source(source)

    assert findings[0].fingerprint == findings[1].fingerprint
    assert [item.occurrence for item in findings] == [0, 1]
    assert len({item.finding_id for item in findings}) == 2


def test_each_call_is_reported_once_even_in_nested_and_deferred_scopes():
    source = code(
        """
        import os

        def outer():
            command = input()

            def inner():
                os.system(command)

            inner()
            run = lambda: os.system(command)
            os.system(command)

        class C:
            def m(self):
                os.system(input())
        """
    )
    findings = scan_source(source)
    positions = [(item.location.line, item.location.column) for item in findings]

    assert len(positions) == len(set(positions))


def test_findings_round_trip_through_a_scan_result():
    findings = scan_source(
        "import os, shlex\nos.system(input())\nos.system(shlex.quote(input()))\n"
    )
    result = ScanResult(status=ScanStatus.COMPLETE, findings=findings)

    assert ScanResult.from_json(result.to_json()) == result
    assert len(result.findings) == 2


def test_rule_matches_the_registry_entry():
    rule = create_default_registry().get("PY-CMD-001")
    finding = scan_source("import os\nos.system(input())\n")[0]

    assert rule is not None
    assert finding.rule_id == rule.rule_id
    assert finding.cwe == rule.cwe
    assert finding.language.value == rule.language


def test_package_root_exports_finding_v2_and_the_legacy_model_stays_importable():
    assert vulnsight.Finding is Finding
    assert vulnsight.models.Finding is not Finding

    legacy = vulnsight.models.Finding(
        function="os.system",
        line=1,
        cwe="CWE-78",
        severity="Review required",
        message="m",
    )

    assert legacy["function"] == "os.system"


def test_legacy_keys_still_work_on_the_new_findings():
    finding = scan_source("import os\nos.system(input())\n")[0]

    assert finding["function"] == "os.system"
    assert finding["cwe"] == "CWE-78"
    assert finding["rule_id"] == "PY-CMD-001"
    assert finding["sink"] == "os.system"
    assert finding["severity"] == "Review required"
    assert finding["source"] == "input()"
    assert finding.get("confidence") == "medium"


def test_old_detector_internals_are_gone():
    assert not hasattr(command_injection, "CommandInjectionVisitor")


# ---------------------------------------------------------------
# The reusable adapter
# ---------------------------------------------------------------


def test_adapter_drops_hits_that_are_not_dangerous():
    source = "import os\nos.system(str(int(input())))\n"
    tree = ast.parse(source)
    hits = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)

    assert len(hits) == 1

    findings = findings_from_hits(
        hits,
        tree,
        describe=lambda hit, effect: "m",
        confidence_by_effect=command_injection.CONFIDENCE_BY_EFFECT,
    )

    assert findings == []


def test_adapter_uses_the_rule_supplied_message_and_confidence():
    tree = ast.parse("import os\nos.system(input())\n")
    hits = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)

    findings = findings_from_hits(
        hits,
        tree,
        describe=lambda hit, effect: f"custom {hit.callee} {effect.value}",
        confidence_by_effect={
            TaintEffect.RAW: ConfidenceLevel.HIGH,
            TaintEffect.PARTIAL: ConfidenceLevel.LOW,
        },
        file="a.py",
    )

    assert findings[0].message == "custom os.system raw"
    assert findings[0].confidence is ConfidenceLevel.HIGH
    assert findings[0].location.file == "a.py"


# ---------------------------------------------------------------
# Adapter: repeated hits for the same call
# ---------------------------------------------------------------


def adapter_findings(hits, tree):
    return findings_from_hits(
        hits,
        tree,
        describe=command_injection.describe,
        confidence_by_effect=command_injection.CONFIDENCE_BY_EFFECT,
    )


def test_the_same_hit_supplied_twice_gives_one_finding():
    tree = ast.parse("import os\nos.system(input())\n")
    hits = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)

    assert len(hits) == 1

    findings = adapter_findings([hits[0], hits[0]], tree)

    assert len(findings) == 1
    assert findings[0].occurrence == 0


def test_a_repeated_hit_among_other_hits_is_dropped_and_order_is_kept():
    tree = ast.parse("import os\nos.system(input())\nos.popen(input())\n")
    first, second = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)

    findings = adapter_findings([first, second, first, second, first], tree)

    assert [item.sink.callee for item in findings] == ["os.system", "os.popen"]


def test_separate_call_nodes_with_identical_content_stay_separate():
    tree = ast.parse("import os\nos.system(input())\nos.system(input())\n")
    hits = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)

    assert len(hits) == 2
    assert hits[0].node is not hits[1].node

    findings = adapter_findings(hits, tree)

    assert len(findings) == 2
    assert findings[0].fingerprint == findings[1].fingerprint
    assert [item.occurrence for item in findings] == [0, 1]


def test_two_calls_on_one_line_stay_separate():
    tree = ast.parse("import os\nos.system(input()); os.system(input())\n")
    hits = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)

    findings = adapter_findings(list(hits) + list(hits), tree)

    assert len(findings) == 2
    assert findings[0].location.column != findings[1].location.column


def test_different_rules_on_the_same_call_are_both_kept():
    other_rule = SinkSpec(
        rule_id="TEST-OTHER-001",
        cwe="CWE-78",
        names=frozenset({"os.system"}),
    )
    tree = ast.parse("import os\nos.system(input())\n")
    hits = TaintVisitor(sink_specs=(SINK_SPECS[0], other_rule)).analyze(tree)

    assert len(hits) == 2
    assert hits[0].node is hits[1].node

    findings = adapter_findings(list(hits) + list(hits), tree)

    assert sorted(item.rule_id for item in findings) == [
        "PY-CMD-001",
        "TEST-OTHER-001",
    ]


def test_the_first_hit_for_a_node_and_rule_is_the_one_kept():
    tree = ast.parse("import os\nos.system(input())\n")
    hit = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)[0]
    messages = []

    def describe(item, effect):
        messages.append(item)

        return "m"

    findings_from_hits(
        [hit, hit],
        tree,
        describe=describe,
        confidence_by_effect=command_injection.CONFIDENCE_BY_EFFECT,
    )

    assert len(messages) == 1


# ---------------------------------------------------------------
# Adapter: duplicate hits with different taint effects
# ---------------------------------------------------------------

# A real engine hit has one effect. To test duplicates that disagree, these
# helpers copy one hit and give each copy the taint of a different snippet.

RAW_SNIPPET = "import os\nos.system(input())\n"
PARTIAL_SNIPPET = "import os, shlex\nos.system(shlex.quote(input()))\n"
NEUTRALIZED_SNIPPET = "import os\nos.system(str(int(input())))\n"


def taint_of(snippet):
    hit = TaintVisitor(sink_specs=SINK_SPECS).analyze(ast.parse(snippet))[0]

    return hit.argument_taints


def variants(*snippets):
    """Return one tree and one hit per snippet, all pointing at that tree's call."""

    tree = ast.parse(RAW_SNIPPET)
    base = TaintVisitor(sink_specs=SINK_SPECS).analyze(tree)[0]
    hits = [
        dataclasses.replace(base, argument_taints=taint_of(snippet))
        for snippet in snippets
    ]

    return tree, hits


def test_the_helper_hits_have_the_effects_they_are_named_for():
    tree, (raw, partial, neutralized) = variants(
        RAW_SNIPPET, PARTIAL_SNIPPET, NEUTRALIZED_SNIPPET
    )

    assert [taint_effect_of(hit) for hit in (raw, partial, neutralized)] == [
        TaintEffect.RAW,
        TaintEffect.PARTIAL,
        TaintEffect.NEUTRALIZED,
    ]
    assert raw.node is partial.node is neutralized.node


def test_a_neutralized_hit_does_not_block_a_later_raw_hit():
    tree, (neutralized, raw) = variants(NEUTRALIZED_SNIPPET, RAW_SNIPPET)

    findings = adapter_findings([neutralized, raw], tree)

    assert len(findings) == 1
    assert findings[0].taint_effect is TaintEffect.RAW
    assert findings[0].confidence is ConfidenceLevel.MEDIUM
    assert len(findings[0].evidence) == 1
    assert not findings[0].evidence[0].neutralizations


def test_a_neutralized_hit_does_not_block_a_later_partial_hit():
    tree, (neutralized, partial) = variants(NEUTRALIZED_SNIPPET, PARTIAL_SNIPPET)

    findings = adapter_findings([neutralized, partial], tree)

    assert len(findings) == 1
    assert findings[0].taint_effect is TaintEffect.PARTIAL
    assert findings[0].confidence is ConfidenceLevel.LOW


def test_a_partial_hit_does_not_block_a_later_raw_hit():
    tree, (partial, raw) = variants(PARTIAL_SNIPPET, RAW_SNIPPET)

    findings = adapter_findings([partial, raw], tree)

    assert len(findings) == 1
    assert findings[0].taint_effect is TaintEffect.RAW
    assert findings[0].confidence is ConfidenceLevel.MEDIUM
    assert "POSIX-specific" not in findings[0].message


def test_a_raw_hit_followed_by_a_partial_hit_stays_raw():
    tree, (raw, partial) = variants(RAW_SNIPPET, PARTIAL_SNIPPET)

    findings = adapter_findings([raw, partial], tree)

    assert len(findings) == 1
    assert findings[0].taint_effect is TaintEffect.RAW
    assert findings[0].confidence is ConfidenceLevel.MEDIUM
    assert "POSIX-specific" not in findings[0].message


def test_two_neutralized_hits_give_no_finding():
    tree, hits = variants(NEUTRALIZED_SNIPPET, NEUTRALIZED_SNIPPET)

    assert adapter_findings(hits, tree) == []


def test_the_order_of_duplicate_hits_does_not_change_the_finding():
    tree, (raw, partial, neutralized) = variants(
        RAW_SNIPPET, PARTIAL_SNIPPET, NEUTRALIZED_SNIPPET
    )

    forward = adapter_findings([neutralized, partial, raw], tree)
    backward = adapter_findings([raw, partial, neutralized], tree)

    assert len(forward) == len(backward) == 1
    assert forward == backward


def test_evidence_of_every_reportable_duplicate_is_kept_without_repeats():
    tree, (raw, partial, neutralized) = variants(
        RAW_SNIPPET, PARTIAL_SNIPPET, NEUTRALIZED_SNIPPET
    )

    findings = adapter_findings([raw, partial, neutralized, raw], tree)
    evidence = findings[0].evidence

    assert len(evidence) == 2
    assert sorted(bool(label.neutralizations) for label in evidence) == [False, True]


def test_two_partial_hits_with_the_same_evidence_give_one_finding_and_one_label():
    tree, hits = variants(PARTIAL_SNIPPET, PARTIAL_SNIPPET)

    findings = adapter_findings(hits, tree)

    assert len(findings) == 1
    assert findings[0].taint_effect is TaintEffect.PARTIAL
    assert len(findings[0].evidence) == 1


def test_the_message_and_sink_come_from_the_strongest_hit():
    tree, (partial, raw) = variants(PARTIAL_SNIPPET, RAW_SNIPPET)
    seen = []

    def describe(hit, effect):
        seen.append(effect)

        return "m"

    findings_from_hits(
        [partial, raw],
        tree,
        describe=describe,
        confidence_by_effect=command_injection.CONFIDENCE_BY_EFFECT,
    )

    assert seen == [TaintEffect.RAW]


def test_a_neutralized_hit_of_one_rule_does_not_affect_another_rule_on_the_call():
    other_rule = SinkSpec(
        rule_id="TEST-OTHER-001",
        cwe="CWE-78",
        names=frozenset({"os.system"}),
    )
    tree = ast.parse(RAW_SNIPPET)
    first, second = TaintVisitor(sink_specs=(SINK_SPECS[0], other_rule)).analyze(tree)
    neutralized = dataclasses.replace(
        first, argument_taints=taint_of(NEUTRALIZED_SNIPPET)
    )

    findings = adapter_findings([neutralized, second], tree)

    assert [item.rule_id for item in findings] == [second.spec.rule_id]
