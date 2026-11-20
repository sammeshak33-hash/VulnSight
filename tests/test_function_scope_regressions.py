import ast

from vulnsight.scanner.specs import ArgSelector, SinkSpec
from vulnsight.scanner.visitor import TaintVisitor

COMMAND_SINK = SinkSpec(
    rule_id="PY-CMD-001",
    cwe="CWE-78",
    names=frozenset({"os.system"}),
    selector=ArgSelector(positions=(0,)),
)


def analyze(source):
    visitor = TaintVisitor(sink_specs=(COMMAND_SINK,))
    return visitor.analyze(ast.parse(source))


def test_function_uses_import_added_after_definition():
    source = """
def execute():
    os.system(input())

import os
"""
    hits = analyze(source)

    assert len(hits) == 1


def test_nested_function_sees_later_closure_assignment():
    source = """
import os

def outer():
    command = "safe"

    def inner():
        os.system(command)

    command = input()
"""
    hits = analyze(source)

    assert len(hits) == 1


def test_match_capture_is_predeclared_as_local():
    source = """
import os

command = "safe"

def execute(value):
    os.system(command)

    match value:
        case command:
            pass
"""
    hits = analyze(source)

    assert hits == ()


def test_nested_function_after_return_is_analyzed():
    source = """
import os

def outer():
    def inner():
        os.system(input())

    return inner
"""

    hits = analyze(source)

    assert len(hits) == 1


def test_function_defined_before_module_raise_is_analyzed():
    source = """
import os

def execute():
    os.system(input())

raise RuntimeError("stop")
"""

    hits = analyze(source)

    assert len(hits) == 1
