from vulnsight.scanner.scope import (
    BindingKind,
    NameCandidate,
    ScopeState,
)
from vulnsight.scanner.taint_model import (
    SourceKind,
    TaintOrigin,
    TaintValue,
)


def make_taint():
    return TaintValue.from_origin(TaintOrigin("input()", SourceKind.INTERACTIVE, 1, 0))


def test_bind_and_retrieve_variable():
    scope = ScopeState()

    scope.bind_name("command")

    assert scope.get("command").kind == BindingKind.VARIABLE


def test_bind_import():
    scope = ScopeState()

    scope.bind_import("os", "os")

    assert scope.get("os").dotted == "os"


def test_bind_parameter_shadows_import():
    scope = ScopeState()

    scope.bind_import("os", "os")
    scope.bind_parameter("os")

    assert scope.get("os").kind == BindingKind.PARAM
    assert scope.resolve_dotted("os.system")[1].value == "none"


def test_scope_copy_is_independent():
    first = ScopeState()
    first.bind_import("os", "os")

    second = first.copy()
    second.bind_name("os")

    assert first.get("os").kind == BindingKind.IMPORT
    assert second.get("os").kind == BindingKind.VARIABLE


def test_join_preserves_taint():
    first = ScopeState()
    first.bind_name("command", taint=make_taint())

    second = ScopeState()
    second.bind_name("command")

    merged = ScopeState.join([first, second])

    assert bool(merged.get_taint("command"))


def test_join_different_bindings_becomes_ambiguous():
    first = ScopeState()
    first.bind_import("os", "os")

    second = ScopeState()
    second.bind_name("os")

    merged = ScopeState.join([first, second])

    assert merged.get("os").kind == BindingKind.AMBIGUOUS


def test_join_name_missing_from_one_path_is_ambiguous():
    first = ScopeState()
    first.bind_import("os", "os")

    second = ScopeState()

    merged = ScopeState.join([first, second])

    assert merged.get("os").kind == BindingKind.AMBIGUOUS
    assert NameCandidate(None) in merged.get("os").candidates


def test_join_same_import_preserves_definite_binding():
    first = ScopeState()
    first.bind_import("os", "os")

    second = ScopeState()
    second.bind_import("os", "os")

    merged = ScopeState.join([first, second])

    assert merged.get("os").kind == BindingKind.IMPORT
    assert merged.get("os").dotted == "os"


def test_unreachable_state_is_ignored():
    first = ScopeState()
    first.bind_name("command", taint=make_taint())

    unreachable = ScopeState(unreachable=True)
    unreachable.bind_name("command")

    merged = ScopeState.join([first, unreachable])

    assert bool(merged.get_taint("command"))
    assert merged.get("command").kind == BindingKind.VARIABLE


def test_all_unreachable_states_remain_unreachable():
    merged = ScopeState.join(
        [
            ScopeState(unreachable=True),
            ScopeState(unreachable=True),
        ]
    )

    assert merged.unreachable
