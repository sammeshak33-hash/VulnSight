"""Differential tests: the new CWE-78 detector against the legacy verdicts.

The legacy verdicts are fixed data in ``tests/differential_corpus.py``. Every
disagreement between the legacy and the new detector must be explained there,
and every explanation must describe a real disagreement.
"""

import pytest

from tests.differential_corpus import CASES
from vulnsight.scanner.command_injection import scan_source

CASES_BY_NAME = {case.name: case for case in CASES}


def new_verdict(source):
    return tuple(
        (
            finding.location.line,
            finding.sink.callee,
            finding.taint_effect.value,
            finding.confidence.value,
        )
        for finding in scan_source(source)
    )


def disagrees(case):
    return tuple((line, callee) for line, callee, _, _ in case.new) != case.old


def test_corpus_holds_the_66_legacy_verdicts():
    assert len(CASES) == 66
    assert len(CASES_BY_NAME) == 66


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_new_detector_matches_the_recorded_verdict(case):
    assert new_verdict(case.source) == case.new


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_every_disagreement_is_explained_and_no_explanation_is_stale(case):
    if disagrees(case):
        assert case.difference, f"{case.name}: unexplained difference"
    else:
        # A note on a case where both detectors agree would be stale.
        assert not case.difference, f"{case.name}: stale explanation"


def test_the_intentional_differences_are_exactly_these():
    assert {case.name for case in CASES if disagrees(case)} == {
        "shadow_param",
        "try_body",
        "match_stmt",
        "shlex_quote",
    }


@pytest.mark.parametrize(
    "name", ["shadow_param", "try_body", "match_stmt", "shlex_quote"]
)
def test_documented_difference_has_a_reason(name):
    assert len(CASES_BY_NAME[name].difference) > 40


def test_legacy_false_positive_on_a_shadowing_parameter_is_gone():
    case = CASES_BY_NAME["shadow_param"]

    assert case.old == ((3, "os.system"),)
    assert case.new == ()


def test_taint_in_try_and_match_is_now_found():
    for name in ("try_body", "match_stmt"):
        case = CASES_BY_NAME[name]

        assert case.old == ()
        assert len(case.new) == 1


def test_shlex_quote_is_reported_as_a_partial_low_confidence_finding():
    case = CASES_BY_NAME["shlex_quote"]

    assert case.old == ()
    assert case.new == ((2, "os.system", "partial", "low"),)


@pytest.mark.parametrize("name", ["int_san", "len_san"])
def test_neutralizing_sanitizers_stay_clean_as_in_the_legacy_detector(name):
    case = CASES_BY_NAME[name]

    assert case.old == ()
    assert case.new == ()


@pytest.mark.parametrize(
    "name",
    ["shell_var", "shell_kwargs", "shell_false", "shell_absent", "shell_one"],
)
def test_unreadable_or_disabled_shell_values_are_not_reported(name):
    case = CASES_BY_NAME[name]

    assert case.old == ()
    assert case.new == ()


def test_the_legacy_recall_on_common_idioms_is_kept():
    for name in (
        "method_on_tainted",
        "method_chain_src",
        "environ_get",
        "environ_sub",
        "getenv",
        "argv_sub",
        "str_format",
        "percent",
        "fstring",
        "augassign",
    ):
        case = CASES_BY_NAME[name]

        assert case.old, name
        assert case.new, name
