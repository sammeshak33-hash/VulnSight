import ast

from vulnsight.scanner.specs import (
    ArgSelector,
    GuardDecision,
    GuardResult,
    SinkSpec,
)
from vulnsight.scanner.visitor import TaintVisitor

COMMAND_SINK = SinkSpec(
    rule_id="PY-CMD-001",
    cwe="CWE-78",
    names=frozenset({"os.system"}),
    selector=ArgSelector(positions=(0,)),
)


def analyze(source, sink=COMMAND_SINK):
    tree = ast.parse(source)
    visitor = TaintVisitor(sink_specs=(sink,))
    hits = visitor.analyze(tree)
    return visitor, hits


def test_comprehension_target_does_not_shadow_module_variable():
    source = """
import os

item = input()

def run():
    values = [item for item in [1]]
    os.system(item)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_walrus_in_list_comprehension_preserves_taint():
    source = """
import os

def run():
    values = [(command := input()) for item in [1]]
    os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_walrus_in_comprehension_filter_preserves_taint():
    source = """
import os

def run():
    values = [item for item in [1] if (command := input())]
    os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_walrus_in_dictionary_comprehension_preserves_taint():
    source = """
import os

def run():
    values = {(command := input()): item for item in [1]}
    os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_nested_comprehension_walrus_preserves_taint():
    source = """
import os

def run():
    values = [
        [(command := input()) for item in row]
        for row in [[1]]
    ]
    os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_unrelated_method_named_system_is_not_a_sink():
    source = """
import custom

custom.system(input())
"""

    _, hits = analyze(source)

    assert len(hits) == 0


def test_exact_os_system_sink_is_still_detected():
    source = """
import os

os.system(input())
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_unknown_sink_guard_retains_finding():
    def unknown_guard(_node):
        return GuardDecision(
            result=GuardResult.UNKNOWN,
            note="Cannot determine whether shell execution is enabled.",
        )

    sink = SinkSpec(
        rule_id="PY-CMD-001",
        cwe="CWE-78",
        names=frozenset({"os.system"}),
        selector=ArgSelector(positions=(0,)),
        guard=unknown_guard,
    )

    source = """
import os

os.system(input())
"""

    _, hits = analyze(source, sink)

    assert len(hits) == 1
