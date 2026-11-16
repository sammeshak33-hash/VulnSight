import pytest

from vulnsight.scanner.taint_model import (
    Neutralization,
    SourceKind,
    TaintEffect,
    TaintOrigin,
    TaintValue,
    TraceKind,
    TraceStep,
)


def make_value():
    origin = TaintOrigin(
        origin_id="input()",
        kind=SourceKind.INTERACTIVE,
        line=3,
        col=10,
    )
    return TaintValue.from_origin(origin)


def test_source_creates_taint_label():
    value = make_value()

    assert len(value.labels) == 1
    assert value.labels[0].origin.origin_id == "input()"
    assert value.labels[0].trace[0].kind == TraceKind.SOURCE


def test_clean_value_has_no_labels():
    assert not TaintValue.clean()


def test_join_combines_origins():
    first = make_value()

    second = TaintValue.from_origin(TaintOrigin("sys.argv", SourceKind.CLI_ARG, 5, 2))

    combined = first.join(second)

    assert len(combined.labels) == 2


def test_trace_step_is_added():
    value = make_value()

    updated = value.with_step(TraceStep(TraceKind.ASSIGN, 4, 2, "command = value"))

    assert len(updated.labels[0].trace) == 2


def test_trace_text_is_limited():
    step = TraceStep(TraceKind.CALL, 1, 0, "x" * 100)

    assert len(step.text) == 80


def test_trace_length_is_limited():
    value = make_value()

    for index in range(20):
        value = value.with_step(TraceStep(TraceKind.ASSIGN, index + 4, 0, "assignment"))

    assert len(value.labels[0].trace) <= 12


def test_posix_quote_does_not_neutralize_windows():
    value = make_value().neutralized(
        Neutralization(
            cwe="CWE-78",
            platforms=frozenset({"posix"}),
            via="shlex.quote",
        )
    )

    assert value.effective_for("CWE-78", {"posix"}) == TaintEffect.NEUTRALIZED

    assert value.effective_for("CWE-78", {"windows"}) == TaintEffect.RAW


def test_partial_platform_neutralization():
    value = make_value().neutralized(
        Neutralization(
            cwe="CWE-78",
            platforms=frozenset({"posix"}),
            via="shlex.quote",
        )
    )

    assert value.effective_for("CWE-78", {"posix", "windows"}) == TaintEffect.PARTIAL


def test_wrong_cwe_does_not_neutralize():
    value = make_value().neutralized(
        Neutralization(
            cwe="CWE-22",
            platforms=frozenset({"posix", "windows"}),
            via="some_path_sanitizer",
        )
    )

    assert value.effective_for("CWE-78", {"posix"}) == TaintEffect.RAW


def test_wildcard_neutralization():
    value = make_value().neutralized(
        Neutralization(
            cwe="*",
            platforms=frozenset({"posix", "windows"}),
            via="int",
        )
    )

    assert (
        value.effective_for("CWE-78", {"posix", "windows"}) == TaintEffect.NEUTRALIZED
    )


def test_clean_effect():
    assert TaintValue.clean().effective_for("CWE-78", {"posix"}) == TaintEffect.CLEAN


def test_invalid_platform_is_rejected():
    with pytest.raises(ValueError):
        Neutralization(
            cwe="CWE-78",
            platforms=frozenset({"linux"}),
            via="test",
        )


def test_signature_ignores_trace_changes():
    first = make_value()

    second = first.with_step(TraceStep(TraceKind.ASSIGN, 4, 0, "command = value"))

    assert first.signature() == second.signature()
