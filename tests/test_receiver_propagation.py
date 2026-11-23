"""Taint propagation through method-call receivers.

Covers the PR 0 fix: ``value.strip()``, ``input().strip()`` and
``os.environ.get("X")`` must carry taint, while clean values, predicates,
unknown methods and user-defined objects must not become tainted.
"""

import textwrap

import pytest

from vulnsight.scanner.policy import TaintPolicy, create_default_policy
from vulnsight.scanner.specs import SinkSpec, SourceSpec
from vulnsight.scanner.taint_model import (
    SourceKind,
    TaintEffect,
    TaintValue,
    TraceKind,
)
from vulnsight.scanner.visitor import (
    CONTAINER_METHODS,
    PROPAGATING_METHODS,
    SOURCE_IDENTITY_STEPS,
    analyze_source,
)

SYSTEM_SINK = SinkSpec(
    rule_id="TEST-CMD-001",
    cwe="CWE-78",
    names=frozenset({"os.system"}),
)


def hits_for(source, policy=None):
    return analyze_source(
        textwrap.dedent(source),
        sink_specs=(SYSTEM_SINK,),
        policy=policy,
    )


def origins(hit):
    return {
        label.origin.origin_id
        for taint in hit.argument_taints
        for label in taint.labels
    }


def effect(hit):
    labels = [label for taint in hit.argument_taints for label in taint.labels]

    return TaintValue(tuple(labels)).effective_for("CWE-78", {"posix", "windows"})


def assert_flagged(source, expected_origins=None, policy=None):
    hits = hits_for(source, policy)

    assert len(hits) == 1, hits

    if expected_origins is not None:
        assert origins(hits[0]) == set(expected_origins)

    return hits[0]


def assert_clean(source, policy=None):
    assert hits_for(source, policy) == ()


# ---------------------------------------------------------------
# The three reported patterns
# ---------------------------------------------------------------


def test_method_on_a_tainted_variable_is_tainted():
    hit = assert_flagged(
        """
        import os
        x = input()
        os.system(x.strip())
        """,
        {"input()"},
    )

    assert effect(hit) == TaintEffect.RAW


def test_method_on_a_source_call_is_tainted():
    hit = assert_flagged(
        """
        import os
        os.system(input().strip())
        """,
        {"input()"},
    )

    assert effect(hit) == TaintEffect.RAW


def test_environ_get_is_tainted():
    hit = assert_flagged(
        """
        import os
        os.system(os.environ.get("X"))
        """,
        {"os.environ"},
    )

    assert effect(hit) == TaintEffect.RAW


# ---------------------------------------------------------------
# More positive cases
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param(
            "import os\nenv = os.environ\nos.system(env.get('X'))",
            {"os.environ"},
            id="environ-alias",
        ),
        pytest.param(
            "import os\nfrom os import environ\nos.system(environ.get('X'))",
            {"os.environ"},
            id="from-import-environ",
        ),
        pytest.param(
            "import os\nos.system(os.environ.copy().get('X'))",
            {"os.environ"},
            id="environ-copy-then-get",
        ),
        pytest.param(
            "import os\nx = input()\nos.system(x.strip().lower())",
            {"input()"},
            id="method-chain",
        ),
        pytest.param(
            "import os\nx = input()\nos.system(x.format(1))",
            {"input()"},
            id="format-on-tainted-template",
        ),
        pytest.param(
            "import os\nx = input()\nos.system(x.split()[0])",
            {"input()"},
            id="split-then-index",
        ),
        pytest.param(
            "import os\nos.system(os.getenv('A').strip())",
            {"os.getenv"},
            id="getenv-then-strip",
        ),
        pytest.param(
            "import os, sys\nos.system(sys.argv[1].strip())",
            {"sys.argv"},
            id="argv-element-then-strip",
        ),
        pytest.param(
            "import os, sys\nos.system(sys.argv.copy()[1])",
            {"sys.argv"},
            id="argv-copy",
        ),
        pytest.param(
            "import os, sys\nos.system(sys.stdin.readline().rstrip())",
            {"sys.stdin"},
            id="stdin-then-rstrip",
        ),
        pytest.param(
            "import os\nos.system(input().encode().decode())",
            {"input()"},
            id="encode-decode",
        ),
    ],
)
def test_more_receiver_patterns_are_tainted(source, expected):
    assert_flagged(source, expected)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            """
            import os
            def run():
                os.system(input().strip())
            """,
            id="in-function",
        ),
        pytest.param(
            """
            import os
            class Runner:
                def go(self):
                    os.system(os.environ.get("X"))
            """,
            id="in-method",
        ),
        pytest.param(
            """
            import os
            x = input()
            def run():
                os.system(x.strip())
            """,
            id="module-variable-read-in-function",
        ),
        pytest.param(
            """
            import os
            def outer():
                x = input()
                def inner():
                    os.system(x.upper())
                inner()
            """,
            id="nested-closure",
        ),
        pytest.param(
            """
            import os
            if cond:
                x = input()
            else:
                x = "ls"
            os.system(x.strip())
            """,
            id="branch-join-keeps-taint",
        ),
        pytest.param(
            """
            import os
            for item in range(3):
                x = input()
                os.system(x.strip())
            """,
            id="in-loop-body",
        ),
    ],
)
def test_receiver_propagation_works_in_every_scope(source):
    assert_flagged(source)


def test_receiver_and_argument_origins_are_both_kept():
    assert_flagged(
        """
        import os
        os.system(input().replace("a", os.environ.get("X")))
        """,
        {"input()", "os.environ"},
    )


def test_receiver_call_adds_a_call_step_to_the_trace():
    hit = assert_flagged(
        """
        import os
        x = input()
        os.system(x.strip())
        """
    )

    trace = hit.argument_taints[0].labels[0].trace

    assert trace[0].kind == TraceKind.SOURCE
    assert trace[-1].kind == TraceKind.CALL


def test_unresolved_receiver_call_keeps_the_existing_trace_text():
    hit = assert_flagged(
        """
        import os
        os.system(input().strip())
        """
    )

    assert hit.argument_taints[0].labels[0].trace[-1].text == "unknown call"


# ---------------------------------------------------------------
# Negative cases: nothing becomes falsely tainted
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("import os\nx = 'ls'\nos.system(x.strip())", id="clean-variable"),
        pytest.param("import os\nos.system('ls'.upper())", id="string-literal"),
        pytest.param("import os\nos.system(os.getcwd().strip())", id="clean-call"),
        pytest.param(
            "import os\nos.system(os.path.join('a', 'b'))",
            id="module-function-named-join",
        ),
        pytest.param(
            "import os\nd = {}\nos.system(d.get('X'))",
            id="clean-dict-get",
        ),
        pytest.param(
            "import os\nd = {'a': 'b'}\nos.system(d.copy()['a'])",
            id="clean-dict-copy",
        ),
        pytest.param(
            "import os\nitems = ['a']\nos.system(items.copy()[0])",
            id="clean-list-copy",
        ),
    ],
)
def test_clean_receivers_stay_clean(source):
    assert_clean(source)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            "import os\nx = input()\nos.system(x.startswith('a'))",
            id="startswith",
        ),
        pytest.param("import os\nx = input()\nos.system(x.isdigit())", id="isdigit"),
        pytest.param("import os\nx = input()\nos.system(x.count('a'))", id="count"),
        pytest.param("import os\nx = input()\nos.system(x.find('a'))", id="find"),
        pytest.param("import os\nx = input()\nos.system(x.run())", id="unknown-method"),
        pytest.param(
            "import os\nx = input()\nos.system('a' if x.startswith('a') else 'b')",
            id="predicate-used-as-condition",
        ),
    ],
)
def test_unlisted_methods_do_not_propagate_receiver_taint(source):
    assert_clean(source)


def test_attribute_read_on_a_tainted_value_is_unchanged():
    # Plain attribute reads are outside this fix and keep their old behaviour.
    assert_clean(
        """
        import os
        x = input()
        os.system(x.real)
        """
    )


# ---------------------------------------------------------------
# get() and copy() on user-defined objects
# ---------------------------------------------------------------


def test_clean_user_object_get_and_copy_stay_clean():
    assert_clean(
        """
        import os
        class Registry:
            def get(self, key):
                return "ls"
            def copy(self):
                return Registry()
        registry = Registry()
        os.system(registry.get("k"))
        os.system(registry.copy().get("k"))
        """
    )


def test_user_object_built_from_a_string_source_does_not_propagate_on_get():
    assert_clean(
        """
        import os
        class Config:
            def __init__(self, value):
                self.value = value
            def get(self, key):
                return "ls"
        config = Config(input())
        os.system(config.get("k"))
        """
    )


def test_user_object_built_from_a_string_source_does_not_propagate_on_copy():
    assert_clean(
        """
        import os
        class Config:
            def __init__(self, value):
                self.value = value
            def copy(self):
                return "ls"
        config = Config(input())
        os.system(config.copy())
        """
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known limitation: a container derived from a string source (for "
        "example json.loads(input())) is not recognised as a mapping, so get() "
        "does not propagate. Revisit when error analysis shows it matters."
    ),
)
def test_known_gap_get_on_parsed_user_input():
    assert_flagged(
        """
        import json, os
        data = json.loads(input())
        os.system(data.get("cmd"))
        """
    )


def test_shadowed_os_does_not_make_environ_a_source():
    assert_clean(
        """
        import os
        os = object()
        os.system(os.environ.get("X"))
        """
    )


def test_local_variable_named_environ_is_not_a_source():
    assert_clean(
        """
        import os
        environ = {}
        os.system(environ.get("X"))
        """
    )


# ---------------------------------------------------------------
# Sanitizers keep working
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "import os\nx = input()\nos.system(str(int(x.strip())))",
        "import os\nx = str(int(input()))\nos.system(x.strip())",
        "import os\nos.system(str(float(input().strip())))",
        "import os\nos.system(str(bool(os.environ.get('X'))))",
        "import os\nos.system('a' * len(input().strip()))",
        "import os\nos.system(str(int(os.environ.get('X'))))",
    ],
    ids=[
        "int-around-receiver-call",
        "receiver-call-after-int",
        "float-around-receiver-call",
        "bool-around-environ-get",
        "len-around-receiver-call",
        "int-around-environ-get",
    ],
)
def test_neutralizing_sanitizers_still_neutralize(source):
    hit = assert_flagged(source)

    assert effect(hit) == TaintEffect.NEUTRALIZED


@pytest.mark.parametrize(
    "source",
    [
        "import os, shlex\nx = shlex.quote(input())\nos.system(x.strip())",
        "import os, shlex\nos.system(shlex.quote(input().strip()))",
        "import os, shlex\nos.system(shlex.quote(os.environ.get('X')))",
    ],
    ids=[
        "receiver-call-after-quote",
        "quote-around-receiver-call",
        "quote-around-environ-get",
    ],
)
def test_shlex_quote_stays_a_partial_neutralization(source):
    hit = assert_flagged(source)

    assert effect(hit) == TaintEffect.PARTIAL


# ---------------------------------------------------------------
# Existing sources and strict-mode parameters
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import os\nos.system(input())", {"input()"}),
        ("import os, sys\nos.system(sys.stdin.read())", {"sys.stdin"}),
        ("import os\nos.system(os.environ['X'])", {"os.environ"}),
        ("import os\nos.system(os.getenv('X'))", {"os.getenv"}),
        ("import os, sys\nos.system(sys.argv[1])", {"sys.argv"}),
    ],
    ids=["input", "stdin-read", "environ-subscript", "getenv", "argv-subscript"],
)
def test_existing_sources_are_still_detected(source, expected):
    assert_flagged(source, expected)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            """
            import os
            def run(command):
                os.system(command.strip())
            """,
            id="parameter-receiver",
        ),
        pytest.param(
            """
            import os
            def run(settings):
                os.system(settings.get("cmd"))
            """,
            id="parameter-get",
        ),
        pytest.param(
            """
            import os
            class Runner:
                def go(self, command):
                    os.system(command.strip().lower())
            """,
            id="method-parameter-chain",
        ),
    ],
)
def test_parameters_stay_clean_as_receivers(source):
    assert_clean(source)


# ---------------------------------------------------------------
# The method lists are pinned
# ---------------------------------------------------------------


def test_propagating_methods_are_pinned():
    assert PROPAGATING_METHODS == frozenset(
        {
            "strip",
            "lstrip",
            "rstrip",
            "lower",
            "upper",
            "casefold",
            "title",
            "capitalize",
            "swapcase",
            "replace",
            "format",
            "format_map",
            "join",
            "split",
            "rsplit",
            "splitlines",
            "partition",
            "rpartition",
            "expandtabs",
            "center",
            "ljust",
            "rjust",
            "zfill",
            "translate",
            "removeprefix",
            "removesuffix",
            "encode",
            "decode",
        }
    )


def test_container_methods_are_pinned():
    assert CONTAINER_METHODS == frozenset({"get", "copy"})


def test_default_policy_declares_exactly_environ_and_argv_as_containers():
    declared = {
        item.origin_id for item in create_default_policy().sources if item.container
    }

    assert declared == {"os.environ", "sys.argv"}


def test_a_container_source_needs_an_origin_id():
    with pytest.raises(ValueError):
        SourceSpec(names=frozenset({"fetch"}), container=True)


def test_method_lists_do_not_overlap():
    assert not PROPAGATING_METHODS & CONTAINER_METHODS


# ---------------------------------------------------------------
# User-defined classes that reuse standard method names
# ---------------------------------------------------------------

# Taint models know a method's name, not the receiver's type. A receiver that
# is the source value itself (``input()``, ``os.environ``, an alias, a
# ``copy()`` of the container) cannot be a user-defined object. Anything that
# passed through a call, such as ``Config(input())``, might be one.


def config_class(*method_names):
    methods = "".join(
        f"    def {name}(self, *args, **kwargs):\n        return 'ls'\n"
        for name in method_names
    )

    return (
        "class Config:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n" + methods
    )


def request_policy():
    """Default policy plus framework and network sources.

    ``request.args`` and ``fetch_headers()`` are declared containers.
    ``fetch_text()`` and ``current_user_name()`` are scalars and are not.
    """

    default = create_default_policy()

    return TaintPolicy(
        sources=default.sources
        + (
            SourceSpec(
                roots=frozenset({"request.args"}),
                kind=SourceKind.FRAMEWORK,
                origin_id="request.args",
                container=True,
            ),
            SourceSpec(
                names=frozenset({"fetch_headers"}),
                kind=SourceKind.NETWORK,
                origin_id="fetch_headers()",
                container=True,
            ),
            SourceSpec(
                names=frozenset({"fetch_text"}),
                kind=SourceKind.NETWORK,
                origin_id="fetch_text()",
            ),
            SourceSpec(
                names=frozenset({"current_user_name"}),
                kind=SourceKind.FRAMEWORK,
                origin_id="current_user_name()",
            ),
        ),
        sanitizers=default.sanitizers,
    )


SOURCE_EXPRESSIONS = [
    pytest.param("os.getenv('X')", id="getenv-string"),
    pytest.param("sys.argv[1]", id="argv-element"),
    pytest.param("os.environ", id="environ-container"),
    pytest.param("request.args", id="framework-container"),
    pytest.param("fetch_text()", id="network-scalar"),
]


@pytest.mark.parametrize("source_expression", SOURCE_EXPRESSIONS)
@pytest.mark.parametrize("method", ["get", "copy"])
def test_user_defined_get_and_copy_are_clean_for_every_source_kind(
    source_expression, method
):
    call = "get('cmd')" if method == "get" else "copy()"

    assert_clean(
        "import os, sys\n"
        + config_class(method)
        + f"os.system(Config({source_expression}).{call})\n",
        policy=request_policy(),
    )


STRING_METHOD_CALLS = [
    pytest.param("strip", "strip()", id="strip"),
    pytest.param("format", "format(1)", id="format"),
    pytest.param("join", "join(['a'])", id="join"),
    pytest.param("split", "split()", id="split"),
    pytest.param("replace", "replace('a', 'b')", id="replace"),
    pytest.param("lower", "lower()", id="lower"),
    pytest.param("encode", "encode()", id="encode"),
]


def test_user_defined_strip_on_an_object_built_from_input_is_clean():
    assert_clean(
        """
        import os

        class Config:
            def __init__(self, value):
                self.value = value

            def strip(self):
                return "ls"

        config = Config(input())
        os.system(config.strip())
        """
    )


@pytest.mark.parametrize(("method", "call"), STRING_METHOD_CALLS)
@pytest.mark.parametrize(
    "source_expression",
    [
        pytest.param("input()", id="input"),
        pytest.param("os.getenv('X')", id="getenv"),
        pytest.param("sys.argv[1]", id="argv"),
    ],
)
def test_user_defined_string_method_names_are_clean_on_wrapped_sources(
    source_expression, method, call
):
    assert_clean(
        "import os, sys\n"
        + config_class(method)
        + f"os.system(Config({source_expression}).{call})\n"
    )


SHADOWING_CLASS = config_class("get", "copy", "strip", "format", "join", "split")


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(
            "os.system(os.environ.get('X'))", {"os.environ"}, id="environ-get"
        ),
        pytest.param(
            "env = os.environ\nos.system(env.get('X'))",
            {"os.environ"},
            id="environ-alias-get",
        ),
        pytest.param(
            "os.system(os.environ.copy().get('X'))",
            {"os.environ"},
            id="environ-copy-then-get",
        ),
        pytest.param(
            "env = os.environ.copy()\nos.system(env.get('X'))",
            {"os.environ"},
            id="environ-copy-assigned-then-get",
        ),
        pytest.param(
            "os.system(sys.argv.copy()[1])", {"sys.argv"}, id="argv-copy-index"
        ),
        pytest.param("os.system(input().strip())", {"input()"}, id="input-strip"),
        pytest.param(
            "x = input()\nos.system(x.strip())", {"input()"}, id="variable-strip"
        ),
        pytest.param(
            "os.system(sys.argv[1].split()[0])", {"sys.argv"}, id="argv-split"
        ),
        pytest.param(
            "os.system(request.args.get('x'))",
            {"request.args"},
            id="framework-container-get",
        ),
    ],
)
def test_source_values_still_propagate_when_the_file_defines_the_same_names(
    body, expected
):
    assert_flagged(
        "import os, sys\n" + SHADOWING_CLASS + body + "\n",
        expected,
        policy=request_policy(),
    )


def test_source_container_identity_survives_aliases_and_copies():
    assert_flagged(
        """
        import os
        env = os.environ.copy()
        alias = env
        os.system(alias.get("X"))
        """,
        {"os.environ"},
    )


def test_shadowed_names_in_a_nested_class_are_found():
    assert_clean(
        """
        import os

        def make():
            class Inner:
                def __init__(self, value):
                    self.value = value

                def strip(self):
                    return "ls"

            return Inner(input())

        def run():
            os.system(make().strip())
        """
    )


def test_class_method_bodies_see_the_module_level_method_names():
    assert_clean(
        """
        import os

        class Config:
            def __init__(self, value):
                self.value = value

            def strip(self):
                return "ls"

            def run(self):
                config = Config(input())
                os.system(config.strip())
        """
    )


def test_known_limitation_shadowed_name_stops_a_chained_call():
    # ``lower`` is defined by a class in this module, so ``.lower()`` on a
    # derived (non-source) string is not propagated. Chained calls on a source
    # value are the price of not guessing the receiver type.
    assert_clean(
        """
        import os

        class Config:
            def lower(self):
                return "ls"

        os.system(input().strip().lower())
        """
    )


def test_known_limitation_imported_class_with_a_standard_name_still_propagates():
    # Only classes defined in the scanned file are known. An imported class
    # with a method called ``strip`` cannot be told apart from ``str.strip``.
    assert_flagged(
        """
        import os
        from helpers import Config

        os.system(Config(input()).strip())
        """,
        {"input()"},
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known limitation: dict(os.environ) is a call, so the result is no "
        "longer recognised as the source container."
    ),
)
def test_known_gap_get_on_a_dict_built_from_environ():
    assert_flagged(
        """
        import os
        os.system(dict(os.environ).get("X"))
        """
    )


def test_source_identity_steps_are_pinned():
    assert SOURCE_IDENTITY_STEPS == frozenset(
        {TraceKind.SOURCE, TraceKind.ASSIGN, TraceKind.ALIAS}
    )


def test_copy_of_a_source_container_is_an_alias_not_a_call():
    hit = assert_flagged(
        """
        import os
        env = os.environ.copy()
        os.system(env["X"])
        """
    )

    kinds = [step.kind for step in hit.argument_taints[0].labels[0].trace]

    assert TraceKind.ALIAS in kinds


# ---------------------------------------------------------------
# Direct sources: container semantics must be declared, not inferred
# ---------------------------------------------------------------

# A source kind says where data comes from, not what type it has. A NETWORK
# or FRAMEWORK source can be a scalar or a custom object, so ``get()`` and
# ``copy()`` propagate only from sources the policy declares as containers.


@pytest.mark.parametrize(
    "source_expression",
    [
        pytest.param("fetch_text()", id="network-scalar"),
        pytest.param("current_user_name()", id="framework-scalar"),
    ],
)
@pytest.mark.parametrize("call", ["get('k')", "copy()"])
def test_undeclared_sources_do_not_propagate_through_get_and_copy(
    source_expression, call
):
    assert_clean(
        f"import os\nos.system({source_expression}.{call})\n",
        policy=request_policy(),
    )


@pytest.mark.parametrize("call", ["get('k')", "copy()"])
def test_undeclared_source_stays_clean_through_an_alias(call):
    assert_clean(
        f"import os\nvalue = fetch_text()\nos.system(value.{call})\n",
        policy=request_policy(),
    )


@pytest.mark.parametrize(
    "source_expression",
    [
        pytest.param("fetch_text()", id="network-scalar"),
        pytest.param("current_user_name()", id="framework-scalar"),
    ],
)
def test_string_methods_still_propagate_from_undeclared_sources(source_expression):
    assert_flagged(
        f"import os\nos.system({source_expression}.strip())\n",
        policy=request_policy(),
    )


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(
            "os.system(os.environ.get('X'))", {"os.environ"}, id="environ-get"
        ),
        pytest.param(
            "env = os.environ\nos.system(env.get('X'))",
            {"os.environ"},
            id="environ-alias",
        ),
        pytest.param(
            "os.system(os.environ.copy().get('X'))",
            {"os.environ"},
            id="environ-copy-get",
        ),
        pytest.param(
            "os.system(sys.argv.copy()[1])", {"sys.argv"}, id="argv-copy-index"
        ),
        pytest.param(
            "os.system(request.args.get('x'))",
            {"request.args"},
            id="declared-framework-container",
        ),
        pytest.param(
            "os.system(request.args.copy().get('x'))",
            {"request.args"},
            id="declared-framework-container-copy",
        ),
        pytest.param(
            "os.system(fetch_headers().get('x'))",
            {"fetch_headers()"},
            id="declared-network-container",
        ),
    ],
)
def test_declared_containers_still_propagate(body, expected):
    assert_flagged("import os, sys\n" + body + "\n", expected, policy=request_policy())


def test_an_origin_id_shared_with_a_scalar_source_is_not_a_container():
    default = create_default_policy()
    policy = TaintPolicy(
        sources=default.sources
        + (
            SourceSpec(
                names=frozenset({"load_a"}),
                origin_id="shared",
                container=True,
            ),
            SourceSpec(names=frozenset({"load_b"}), origin_id="shared"),
        ),
        sanitizers=default.sanitizers,
    )

    assert_clean("import os\nos.system(load_a().get('k'))\n", policy=policy)


# ---------------------------------------------------------------
# Built-in method, user-defined method, imported class
# ---------------------------------------------------------------


def test_builtin_method_on_a_source_value_propagates():
    assert_flagged("import os\nos.system(input().strip())\n", {"input()"})


def test_user_defined_method_with_the_same_name_does_not_propagate():
    assert_clean(
        "import os\n" + config_class("strip") + "os.system(Config(input()).strip())\n"
    )


def test_class_attribute_assigned_a_function_counts_as_user_defined():
    assert_clean(
        """
        import os

        def constant(self):
            return "ls"

        class Config:
            def __init__(self, value):
                self.value = value

            strip = constant

        os.system(Config(input()).strip())
        """
    )


def test_annotated_class_attribute_counts_as_user_defined():
    assert_clean(
        """
        import os

        class Config:
            strip: object = None

            def __init__(self, value):
                self.value = value

        os.system(Config(input()).strip())
        """
    )


def test_known_limitation_class_inheriting_from_an_imported_base_still_propagates():
    # ``strip`` may come from the imported base class, which is not visible.
    assert_flagged(
        """
        import os
        from helpers import Base

        class Config(Base):
            pass

        os.system(Config(input()).strip())
        """,
        {"input()"},
    )


def test_known_limitation_object_from_an_unresolved_factory_still_propagates():
    assert_flagged(
        """
        import os
        import helpers

        os.system(helpers.make(input()).strip())
        """,
        {"input()"},
    )


@pytest.mark.parametrize("call", ["get('k')", "copy()"])
def test_imported_class_get_and_copy_on_a_wrapped_container_are_clean(call):
    # The constructor call breaks source identity, so get() and copy() do not
    # propagate even though the class itself cannot be inspected.
    assert_clean(
        f"""
        import os
        from helpers import Config

        os.system(Config(os.environ).{call})
        """
    )
