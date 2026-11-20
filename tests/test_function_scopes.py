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
    hits = visitor.analyze(ast.parse(source))
    return visitor, hits


def test_function_parameter_is_clean_by_default():
    source = """
import os

def execute(command):
    os.system(command)
"""
    _, hits = analyze(source)

    assert hits == ()


def test_source_inside_function_is_detected():
    source = """
import os

def execute():
    command = input()
    os.system(command)
"""
    _, hits = analyze(source)

    assert len(hits) == 1


def test_function_body_analyzed_without_call():
    source = """
import os

def execute():
    os.system(input())
"""
    _, hits = analyze(source)

    assert len(hits) == 1


def test_local_import_shadowing():
    source = """
import os

def execute():
    os = object()
    os.system(input())
"""
    _, hits = analyze(source)

    assert hits == ()


def test_assignment_shadows_import_before_assignment():
    source = """
import os

def execute():
    os.system(input())
    os = object()
"""
    _, hits = analyze(source)

    assert hits == ()


def test_module_import_available_in_function():
    source = """
import os

def execute():
    os.system(input())
"""
    _, hits = analyze(source)

    assert len(hits) == 1


def test_nested_function_is_analyzed():
    source = """
import os

def outer():
    def inner(command):
        os.system(command)
"""
    _, hits = analyze(source)

    assert hits == ()


def test_class_body_and_method_are_separate():
    source = """
import os

class Runner:
    command = input()
    os.system(command)

    def execute(self, command):
        os.system(command)
"""
    _, hits = analyze(source)

    assert len(hits) == 1
    assert {hit.scope_kind for hit in hits} == {"class"}


def test_class_attribute_does_not_leak_into_method():
    source = """
import os

class Runner:
    command = input()

    def execute(self):
        os.system(command)
"""
    _, hits = analyze(source)

    assert hits == ()


def test_global_assignment_is_visible_inside_function():
    source = """
import os

command = "dir"

def update():
    global command
    command = input()
    os.system(command)
"""
    _, hits = analyze(source)

    assert len(hits) == 1
    assert hits[0].scope_kind == "function"


def test_nonlocal_assignment_updates_closure_scope():
    source = """
import os

def outer():
    command = "dir"

    def inner():
        nonlocal command
        command = input()
        os.system(command)
"""
    _, hits = analyze(source)

    assert len(hits) == 1
