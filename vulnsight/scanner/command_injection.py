"""OS command injection (CWE-78) detector built on the taint engine.

The detector is a thin layer over ``TaintVisitor``: it declares the sinks, adds
the ``shell=True`` rule for ``subprocess``, and turns the engine's sink hits
into Finding v2 objects through ``vulnsight.scanner.adapter``.
"""

import ast

from vulnsight.findings import ConfidenceLevel
from vulnsight.scanner.adapter import findings_from_hits
from vulnsight.scanner.specs import (
    GuardDecision,
    GuardResult,
    SinkSpec,
)
from vulnsight.scanner.taint_model import TaintEffect
from vulnsight.scanner.visitor import TaintVisitor

RULE_ID = "PY-CMD-001"
CWE = "CWE-78"

OS_SINKS = {
    "os.system",
    "os.popen",
}

SUBPROCESS_SINKS = {
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}

# A subprocess call whose ``shell`` value cannot be read from the source (a
# variable, an expression or ``**options``) gets the guard result UNKNOWN. The
# legacy detector never reported those calls, so M1.2 keeps them suppressed.
# Setting this to True reports them instead.
REPORT_UNKNOWN_SHELL = False

CONFIDENCE_BY_EFFECT = {
    TaintEffect.RAW: ConfidenceLevel.MEDIUM,
    # ``shlex.quote`` quotes for POSIX shells only. It is not safe escaping for
    # Windows ``cmd.exe``, so a quoted value is still reported, with low
    # confidence.
    TaintEffect.PARTIAL: ConfidenceLevel.LOW,
}

PARTIAL_NOTE = (
    "sanitizer does not cover every platform; shlex.quote is POSIX-specific "
    "and is not safe Windows command escaping"
)


def shell_guard(node):
    """Decide whether a subprocess call runs its command through a shell.

    * ``shell=True`` (the literal) applies.
    * No ``shell`` argument, or any other constant (``False``, ``None``, ``1``),
      does not apply. Only the literal ``True`` counts.
    * A ``shell`` value that is not a constant, or ``**options`` without an
      explicit ``shell``, is unknown.
    """

    has_unpacked_options = False

    for keyword in node.keywords:
        if keyword.arg is None:
            has_unpacked_options = True
        elif keyword.arg == "shell":
            if isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    return GuardDecision(GuardResult.APPLIES)

                return GuardDecision(
                    GuardResult.NOT_APPLICABLE,
                    "shell is not the literal True",
                )

            return GuardDecision(
                GuardResult.UNKNOWN,
                "shell value is not a constant",
            )

    if has_unpacked_options:
        return GuardDecision(
            GuardResult.UNKNOWN,
            "shell may be set through **options",
        )

    return GuardDecision(
        GuardResult.NOT_APPLICABLE,
        "shell is not set",
    )


SINK_SPECS = (
    SinkSpec(
        rule_id=RULE_ID,
        cwe=CWE,
        names=frozenset(OS_SINKS),
    ),
    SinkSpec(
        rule_id=RULE_ID,
        cwe=CWE,
        names=frozenset(SUBPROCESS_SINKS),
        guard=shell_guard,
    ),
)


def describe(hit, effect):
    """Return the finding message for one sink hit."""

    message = f"Potential command injection: tainted data reaches {hit.callee}"

    if effect == TaintEffect.PARTIAL:
        message = f"{message} ({PARTIAL_NOTE})"

    return message


def detect(tree, *, file=None, policy=None):
    """Find command injection in a parsed module.

    ``tree`` is an ``ast.Module``. ``file`` is the path recorded on each
    finding (``None`` for in-memory source). The result is a list of Finding v2
    objects in canonical order.
    """

    hits = TaintVisitor(policy=policy, sink_specs=SINK_SPECS).analyze(tree)

    if not REPORT_UNKNOWN_SHELL:
        hits = tuple(hit for hit in hits if hit.guard.result != GuardResult.UNKNOWN)

    return findings_from_hits(
        hits,
        tree,
        describe=describe,
        confidence_by_effect=CONFIDENCE_BY_EFFECT,
        file=file,
    )


def scan_source(source_code):
    """Scan Python source code for potential command injection.

    Returns a list of Finding v2 objects. Raises ``ValueError`` when the source
    is not valid Python.
    """

    try:
        tree = ast.parse(source_code)
    except SyntaxError as error:
        raise ValueError(f"Invalid Python source code: {error}") from error

    return detect(tree)


if __name__ == "__main__":
    sample_code = """
import os

filename = input("Enter filename: ")
command = "type " + filename
os.system(command)
"""

    for finding in scan_source(sample_code):
        print(finding.to_dict())
