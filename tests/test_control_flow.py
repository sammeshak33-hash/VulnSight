import ast

from vulnsight.scanner.specs import ArgSelector, SinkSpec
from vulnsight.scanner.taint_model import TaintEffect
from vulnsight.scanner.visitor import TaintVisitor

COMMAND_SINK = SinkSpec(
    rule_id="PY-CMD-001",
    cwe="CWE-78",
    names=frozenset({"os.system"}),
    selector=ArgSelector(positions=(0,)),
)


def analyze(source):
    tree = ast.parse(source)

    visitor = TaintVisitor(sink_specs=(COMMAND_SINK,))
    hits = visitor.analyze(tree)

    return visitor, hits


def test_if_branch_preserves_possible_taint():
    source = """
import os

if condition:
    command = input()
else:
    command = "dir"

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_if_both_safe_branches_remain_clean():
    source = """
import os

if condition:
    command = "dir"
else:
    command = "echo hello"

os.system(command)
"""

    _, hits = analyze(source)

    assert hits == ()


def test_for_loop_target_inherits_iterable_taint():
    source = """
import os
import sys

for command in sys.argv:
    os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_for_loop_preserves_zero_iteration_path():
    source = """
import os

command = "dir"

for item in items:
    command = input()

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_while_loop_preserves_possible_taint():
    source = """
import os

command = "dir"

while condition:
    command = input()

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_break_does_not_discard_tainted_path():
    source = """
import os

while condition:
    command = input()
    break

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_continue_path_preserves_possible_taint():
    source = """
import os

command = "dir"

for item in items:
    command = input()
    continue

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_try_except_merges_possible_taint():
    source = """
import os

try:
    command = input()
except Exception:
    command = "dir"

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_try_else_preserves_taint():
    source = """
import os

try:
    command = input()
except Exception:
    command = "dir"
else:
    marker = 1

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_finally_does_not_clear_taint():
    source = """
import os

try:
    command = input()
finally:
    marker = 1

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_match_capture_inherits_subject_taint():
    source = """
import os

match input():
    case command:
        os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_match_without_default_keeps_unmatched_path():
    source = """
import os

command = "dir"

match choice:
    case 1:
        command = input()

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_with_target_does_not_inherit_context_expression_taint():
    source = """
import os

with input() as command:
    os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 0


def test_nested_control_flow_preserves_taint():
    source = """
import os

if condition:
    for item in items:
        command = input()
else:
    command = "dir"

os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_sink_hit_contains_rule_and_source_trace():
    source = """
import os

command = input()
os.system(command)
"""

    _, hits = analyze(source)

    assert len(hits) == 1

    hit = hits[0]

    assert hit.spec.rule_id == "PY-CMD-001"
    assert hit.spec.cwe == "CWE-78"
    assert hit.callee == "os.system"
    assert hit.argument_taints[0]
    assert (
        hit.argument_taints[0].effective_for(
            "CWE-78",
            {"posix"},
        )
        == TaintEffect.RAW
    )


def test_direct_input_to_sink_is_detected():
    source = """
import os

os.system(input())
"""

    _, hits = analyze(source)

    assert len(hits) == 1


def test_clean_sink_argument_is_not_reported():
    source = """
import os

os.system("dir")
"""

    _, hits = analyze(source)

    assert hits == ()


def test_loop_else_does_not_receive_break_path_taint():
    source = """
import os

command = "echo safe"

for item in items:
    command = input()
    break
else:
    os.system(command)
"""

    _, hits = analyze(source)

    assert hits == ()
