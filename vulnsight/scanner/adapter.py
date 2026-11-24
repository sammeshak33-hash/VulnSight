"""Turn taint-engine sink hits into Finding v2 objects.

The taint engine reports a ``SinkHit`` for every sink that receives tainted
data, even when a sanitizer has neutralized that data. Rules use this module to
turn hits into findings. It owns everything that is the same for every rule:

* dropping hits whose taint is fully neutralized;
* the source location;
* the enclosing function name;
* the evidence and the sink;
* canonical ordering and occurrence numbers.

A rule supplies only what is its own: the message and the confidence. The
module never changes the engine and never runs or imports scanned code.
"""

import ast

from vulnsight.findings import (
    ConfidenceLevel,
    Finding,
    Language,
    Location,
    Sink,
    assign_occurrences,
)
from vulnsight.scanner.taint_model import TaintEffect, TaintValue

# Platforms a finding is judged against. A sanitizer must cover all of them to
# neutralize a flow completely, so ``shlex.quote`` (POSIX only) leaves a
# command-injection flow partly neutralized.
DEFAULT_PLATFORMS = frozenset({"posix", "windows"})

MODULE_NAME = "<module>"

# Effects that produce a finding, strongest first. A fully neutralized flow
# produces none.
EFFECT_STRENGTH = {
    TaintEffect.RAW: 0,
    TaintEffect.PARTIAL: 1,
}


def build_parent_map(tree):
    """Map every node of ``tree`` to its parent node."""

    parents = {}

    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    return parents


def _in_body(child, body):
    """Check whether ``child`` is one of the statements in ``body``."""

    return any(child is statement for statement in body)


def enclosing_function_name(node, parents):
    """Return the engine's qualified name for the scope that runs ``node``.

    This mirrors how ``TaintVisitor`` names scopes (``_qualname`` and
    ``visit_Lambda``):

    * Module level is ``"<module>"``.
    * A function or class adds its name to the name of its enclosing scope,
      joined with ``.``. Methods are ``Class.method`` and nested functions are
      ``outer.inner``.
    * A lambda is ``"<lambda@LINE>"`` and does not take its parent's prefix.
    * A statement in a class body belongs to the class, so it gets the class
      name.
    * A decorator, default value, annotation, base class or class keyword is
      evaluated in the scope that contains the definition, not inside it.
    """

    scopes = []
    child = node
    parent = parents.get(child)

    while parent is not None:
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if _in_body(child, parent.body):
                scopes.append(parent)
        elif isinstance(parent, ast.Lambda):
            if child is parent.body:
                scopes.append(parent)

        child = parent
        parent = parents.get(child)

    name = MODULE_NAME

    for scope in reversed(scopes):
        if isinstance(scope, ast.Lambda):
            name = f"<lambda@{scope.lineno}>"
        elif name == MODULE_NAME:
            name = scope.name
        else:
            name = f"{name}.{scope.name}"

    return name


def taint_effect_of(hit, platforms=DEFAULT_PLATFORMS):
    """Return how much of the tainted data still reaches the sink."""

    labels = tuple(label for taint in hit.argument_taints for label in taint.labels)

    return TaintValue(labels).effective_for(hit.spec.cwe, platforms)


def findings_from_hits(
    hits,
    tree,
    *,
    describe,
    confidence_by_effect,
    file=None,
    language=Language.PYTHON,
    platforms=DEFAULT_PLATFORMS,
):
    """Build Finding v2 objects from engine sink hits.

    ``tree`` must be the module the engine analyzed, because hits point at
    nodes of that tree. ``describe(hit, effect)`` returns the message.
    ``confidence_by_effect`` maps ``TaintEffect.RAW`` and ``TaintEffect.PARTIAL``
    to a ``ConfidenceLevel``.

    Hits whose taint is fully neutralized (or not tainted at all) produce no
    finding and never hide another hit. The result has at most one finding per
    call node and rule, in canonical order with occurrence numbers assigned.

    The engine can report the same call more than once. The reportable hits
    for one node and rule are merged:

    * the strongest effect wins (``RAW`` over ``PARTIAL``), and it decides the
      confidence and the message;
    * the evidence is the union of the labels of all reportable hits;
    * the sink comes from the first hit with the strongest effect.

    Different call nodes stay separate even when they look identical, and
    different rules on one call stay separate.
    """

    parents = build_parent_map(tree)
    reportable = {}

    for hit in hits:
        effect = taint_effect_of(hit, platforms)

        if effect not in EFFECT_STRENGTH:
            continue

        reportable.setdefault((hit.node, hit.spec.rule_id), []).append((hit, effect))

    findings = []

    for group in reportable.values():
        effect = min((item[1] for item in group), key=EFFECT_STRENGTH.get)
        hit = next(item[0] for item in group if item[1] == effect)
        node = hit.node
        labels = []

        for member, _ in group:
            for taint in member.argument_taints:
                for label in taint.labels:
                    if label not in labels:
                        labels.append(label)

        findings.append(
            Finding(
                rule_id=hit.spec.rule_id,
                cwe=hit.spec.cwe,
                language=language,
                message=describe(hit, effect),
                location=Location(
                    file,
                    node.lineno,
                    node.col_offset,
                    node.end_lineno,
                    node.end_col_offset,
                ),
                confidence=ConfidenceLevel(confidence_by_effect[effect]),
                enclosing_function=enclosing_function_name(node, parents),
                sink=Sink(hit.callee, hit.certainty),
                evidence=tuple(labels),
                taint_effect=effect,
            )
        )

    return list(assign_occurrences(findings))
