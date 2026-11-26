"""Tests for matching, counts and metrics."""

import itertools
import random

import pytest

from tests.finding_builders import make_finding
from vulnsight.eval import (
    LINE_TOLERANCE,
    Benchmark,
    BenchmarkCase,
    Counts,
    EvaluationResult,
    ExpectedFinding,
    evaluate,
    evaluate_case,
    is_compatible,
)
from vulnsight.findings import Language, Location


def finding(cwe="CWE-78", file="a.py", line=10, **overrides):
    return make_finding(cwe=cwe, location=Location(file, line, 0), **overrides)


def exp(expected_id, cwe="CWE-78", file=None, line=None):
    return ExpectedFinding(expected_id, cwe, file, line)


def case(*items, case_id="c1", language=Language.PYTHON):
    return BenchmarkCase(case_id, language, tuple(items))


def run(items, findings, language=Language.PYTHON):
    return evaluate_case(case(*items, language=language), findings)


def pairs(result):
    return {m.expected_id: m.finding.location.line for m in result.matches}


# -- compatibility -----------------------------------------------------


def test_tolerance_is_a_fixed_constant_of_five():
    assert LINE_TOLERANCE == 5


@pytest.mark.parametrize(
    ("actual_line", "ok"),
    [(10, True), (5, True), (15, True), (4, False), (16, False), (11, True)],
)
def test_line_tolerance_boundaries(actual_line, ok):
    assert is_compatible(exp("e", line=10), finding(line=actual_line)) is ok


def test_only_starting_line_is_used_not_the_span():
    spanning = make_finding(location=Location("a.py", 3, 0, 40, 0))

    assert is_compatible(exp("e", line=10), spanning) is False
    assert is_compatible(exp("e", line=8), spanning) is True


def test_cwe_must_match_exactly():
    assert is_compatible(exp("e", cwe="CWE-79"), finding()) is False
    assert is_compatible(exp("e", cwe="CWE-7"), finding(cwe="CWE-78")) is False


def test_file_comparison_is_exact_and_case_sensitive():
    assert is_compatible(exp("e", file="a.py"), finding(file="a.py")) is True
    assert is_compatible(exp("e", file="A.py"), finding(file="a.py")) is False
    assert is_compatible(exp("e", file="b.py"), finding(file="a.py")) is False
    assert is_compatible(exp("e", file="a.py"), finding(file="src/a.py")) is False


def test_windows_separators_in_expected_file_match_normalized_findings():
    assert is_compatible(exp("e", file="src\\a.py"), finding(file="src\\a.py"))
    assert is_compatible(exp("e", file="src\\a.py"), finding(file="src/a.py"))


def test_expected_file_never_matches_a_finding_without_a_file():
    assert is_compatible(exp("e", file="a.py"), finding(file=None)) is False


def test_unspecified_location_parts_impose_no_constraint():
    anywhere = finding(file="zzz.py", line=9999)

    assert is_compatible(exp("e"), anywhere)
    assert is_compatible(exp("e", file="zzz.py"), anywhere)
    assert is_compatible(exp("e", line=9999), anywhere)
    assert is_compatible(exp("e"), finding(file=None))


def test_other_fields_are_ignored():
    odd = finding(rule_id="X-1", message="other")

    assert is_compatible(exp("e", file="a.py", line=10), odd)


# -- counts -----------------------------------------------------------


def test_counts_validate_integers_and_reject_bool():
    for bad in (True, False, 1.0, "1", None, -1):
        for field in ("tp", "fp", "fn"):
            with pytest.raises(ValueError, match=field):
                Counts(**{field: bad})

    assert Counts(0, 0, 0) == Counts()


def test_metric_values():
    counts = Counts(tp=6, fp=2, fn=3)

    assert counts.precision == 6 / 8
    assert counts.recall == 6 / 9
    assert counts.f1 == 12 / 17
    assert counts.f1 == pytest.approx(
        2 * counts.precision * counts.recall / (counts.precision + counts.recall)
    )


@pytest.mark.parametrize(
    ("counts", "precision", "recall", "f1"),
    [
        (Counts(0, 0, 0), 0.0, 0.0, 0.0),
        (Counts(0, 3, 0), 0.0, 0.0, 0.0),
        (Counts(0, 0, 4), 0.0, 0.0, 0.0),
        (Counts(0, 2, 2), 0.0, 0.0, 0.0),
        (Counts(5, 0, 0), 1.0, 1.0, 1.0),
        (Counts(2, 0, 2), 1.0, 0.5, 2 / 3),
    ],
)
def test_undefined_and_edge_metrics_are_zero_or_exact(counts, precision, recall, f1):
    assert counts.precision == precision
    assert counts.recall == recall
    assert counts.f1 == pytest.approx(f1)
    for value in (counts.precision, counts.recall, counts.f1):
        assert isinstance(value, float)


def test_counts_add():
    assert Counts(1, 2, 3) + Counts(4, 5, 6) == Counts(5, 7, 9)

    with pytest.raises(TypeError):
        Counts() + 1


# -- basic matching ---------------------------------------------------


def test_simple_match_and_unmatched_sides():
    actual_hit, actual_extra = finding(line=10), finding(cwe="CWE-79", line=1)
    result = run(
        [exp("e1", line=10), exp("e2", cwe="CWE-89")], [actual_hit, actual_extra]
    )

    assert [m.expected_id for m in result.matches] == ["e1"]
    assert result.matches[0].finding == actual_hit
    assert [e.expected_id for e in result.unmatched_expected] == ["e2"]
    assert result.unmatched_actual == (actual_extra,)
    assert result.counts == Counts(tp=1, fp=1, fn=1)


def test_empty_prediction_sequence_gives_only_false_negatives():
    result = run([exp("e1"), exp("e2")], [])

    assert result.counts == Counts(0, 0, 2)
    assert result.matches == ()


def test_no_expectations_makes_every_finding_a_false_positive():
    result = run([], [finding(), finding(line=50)])

    assert result.counts == Counts(0, 2, 0)


def test_tuple_and_list_predictions_both_work():
    assert run([exp("e")], (finding(),)).counts.tp == 1
    assert run([exp("e")], [finding()]).counts.tp == 1


def test_one_to_one_a_finding_cannot_satisfy_two_expectations():
    result = run([exp("e1"), exp("e2")], [finding()])

    assert result.counts == Counts(1, 0, 1)


def test_duplicate_actual_findings_are_preserved_as_false_positives():
    twin = finding()
    result = run([exp("e1")], [twin, twin, twin])

    assert result.counts == Counts(1, 2, 0)
    assert len(result.unmatched_actual) == 2


def test_duplicate_actual_findings_can_satisfy_duplicate_expectations():
    result = run([exp("e1"), exp("e2")], [finding(), finding()])

    assert result.counts == Counts(2, 0, 0)


def test_findings_with_equal_ids_are_still_counted_separately():
    first = finding()
    clone = finding()

    assert first.finding_id == clone.finding_id
    assert run([exp("a"), exp("b")], [first, clone]).counts.tp == 2


# -- maximum cardinality ------------------------------------------------


def test_maximum_cardinality_beats_a_greedy_first_choice():
    # e1 is compatible with both findings, e2 only with the first one.
    # Greedy would give e1 the first finding and leave e2 unmatched.
    near, far = finding(line=10), finding(line=15)
    result = run([exp("e1", line=12), exp("e2", line=6)], [near, far])

    assert result.counts.tp == 2
    assert pairs(result) == {"e1": 15, "e2": 10}


def test_alternating_path_of_length_three():
    f1, f2, f3 = finding(line=10), finding(line=20), finding(line=30)
    items = [exp("a", line=10), exp("b", line=15), exp("c", line=25), exp("d", line=30)]
    # a-f1 ; b-f1,f2 ; c-f2,f3 ; d-f3
    result = run(items, [f1, f2, f3])

    assert result.counts.tp == 3
    assert result.counts.fn == 1


def test_line_distance_is_not_optimized_at_the_cost_of_cardinality():
    result = run(
        [exp("e1", line=10), exp("e2", line=10)],
        [finding(line=10), finding(line=15)],
    )

    assert result.counts.tp == 2
    assert pairs(result) == {"e1": 10, "e2": 15}


def test_line_distance_is_not_used_to_choose_among_equal_options():
    # Both findings fit e1. The pairing follows canonical order (line 8 first),
    # even though line 12 is closer to the expected line 12.
    result = run([exp("e1", line=12)], [finding(line=12), finding(line=8)])

    assert pairs(result) == {"e1": 8}


def brute_force_maximum(expected, actual):
    best = 0

    def search(index, used, size):
        nonlocal best
        best = max(best, size)
        if index == len(expected):
            return
        search(index + 1, used, size)
        for j, candidate in enumerate(actual):
            if j not in used and is_compatible(expected[index], candidate):
                search(index + 1, used | {j}, size + 1)

    search(0, frozenset(), 0)

    return best


def test_cardinality_equals_brute_force_on_random_cases():
    rng = random.Random(1234)

    for _ in range(300):
        items = [
            exp(
                f"e{i}",
                cwe=rng.choice(["CWE-78", "CWE-79"]),
                file=rng.choice([None, "a.py", "b.py"]),
                line=rng.choice([None, 1, 7, 13, 20]),
            )
            for i in range(rng.randint(0, 6))
        ]
        found = [
            finding(
                cwe=rng.choice(["CWE-78", "CWE-79"]),
                file=rng.choice(["a.py", "b.py"]),
                line=rng.choice([1, 4, 9, 14, 20, 26]),
            )
            for _ in range(rng.randint(0, 6))
        ]

        result = run(items, found)

        assert result.counts.tp == brute_force_maximum(list(items), found)
        assert result.counts.tp + result.counts.fp == len(found)
        assert result.counts.tp + result.counts.fn == len(items)
        for match in result.matches:
            assert is_compatible(match.expected, match.finding)


# -- specificity priority -----------------------------------------------


def test_more_specific_expected_finding_wins_a_contested_finding():
    only = finding(file="a.py", line=10)
    result = run(
        [exp("a-loose"), exp("z-precise", file="a.py", line=10)],
        [only],
    )

    assert [m.expected_id for m in result.matches] == ["z-precise"]
    assert [e.expected_id for e in result.unmatched_expected] == ["a-loose"]


def test_specificity_two_beats_one_beats_zero():
    only = finding(file="a.py", line=10)
    items = [
        exp("zero"),
        exp("line-only", line=10),
        exp("file-only", file="a.py"),
        exp("both", file="a.py", line=10),
    ]

    assert [m.expected_id for m in run(items, [only]).matches] == ["both"]
    # Equal specificity: canonical order decides (no file sorts before a file).
    assert [m.expected_id for m in run(items[:3], [only]).matches] == ["line-only"]
    assert [m.expected_id for m in run([items[0], items[1]], [only]).matches] == [
        "line-only"
    ]


def test_specificity_never_reduces_cardinality():
    # The precise expectation could take the only finding the loose one needs.
    f1, f2 = finding(file="a.py", line=10), finding(file="b.py", line=10)
    result = run([exp("precise", file="a.py", line=10), exp("loose")], [f1, f2])

    assert result.counts.tp == 2
    assert result.matches[1].finding == f1 or result.matches[0].finding == f1
    assert {m.expected_id: m.finding.location.file for m in result.matches} == {
        "precise": "a.py",
        "loose": "b.py",
    }


def test_equal_specificity_ties_break_by_canonical_order_not_input_order():
    only = finding()
    one = run([exp("b"), exp("a")], [only])
    two = run([exp("a"), exp("b")], [only])

    assert [m.expected_id for m in one.matches] == ["a"]
    assert one == two


# -- determinism --------------------------------------------------------


def varied_findings():
    return [
        finding(line=10),
        finding(line=10, message="other text"),
        finding(line=12, rule_id="PY-CMD-002"),
        finding(file="b.py", line=3),
        finding(cwe="CWE-79", line=11),
        finding(file=None, line=10),
        finding(line=10),
    ]


def test_every_permutation_of_predictions_gives_the_same_result():
    items = [exp("e1", line=11), exp("e2", file="a.py"), exp("e3", cwe="CWE-79")]
    found = varied_findings()[:5]
    reference = run(items, found)

    for ordering in itertools.permutations(found):
        assert run(items, list(ordering)) == reference


def test_every_permutation_of_expectations_gives_the_same_result():
    items = [exp("e1", line=11), exp("e2", file="a.py"), exp("e3"), exp("e4", line=3)]
    found = varied_findings()
    reference = run(items, found)

    for ordering in itertools.permutations(items):
        assert run(ordering, found) == reference


def test_shuffled_inputs_with_ties_and_duplicates_are_stable():
    rng = random.Random(7)
    items = [exp(f"e{i}", line=rng.choice([None, 10, 12])) for i in range(5)]
    found = varied_findings() * 2
    reference = run(items, found)

    for _ in range(100):
        shuffled_items, shuffled_found = list(items), list(found)
        rng.shuffle(shuffled_items)
        rng.shuffle(shuffled_found)

        assert run(shuffled_items, shuffled_found) == reference


def test_unmatched_actual_order_is_canonical_not_input_order():
    late, early = finding(line=40), finding(line=2)

    assert run([], [late, early]).unmatched_actual == (early, late)
    assert run([], [early, late]).unmatched_actual == (early, late)


def test_findings_differing_only_in_occurrence_are_ordered_canonically():
    a = finding()
    b = finding(occurrence=2)

    assert a.finding_id != b.finding_id
    assert run([exp("e1"), exp("e2")], [a, b]).counts.tp == 2
    assert run([exp("e1"), exp("e2")], [b, a]) == run([exp("e1"), exp("e2")], [a, b])


# -- validation ---------------------------------------------------------


def test_language_mismatch_is_rejected():
    with pytest.raises(ValueError, match="python.*c"):
        run([exp("e")], [make_finding(language=Language.C)])


def test_language_mismatch_is_rejected_even_for_an_empty_expectation_case():
    with pytest.raises(ValueError, match="finding is"):
        run([], [make_finding(language=Language.CPP)])


@pytest.mark.parametrize("bad", ["abc", b"abc", None, 5, {1}, iter([finding()])])
def test_predictions_must_be_a_sequence(bad):
    with pytest.raises(ValueError, match="sequence"):
        run([exp("e")], bad)


def test_predictions_must_hold_findings():
    with pytest.raises(ValueError, match="Finding"):
        run([exp("e")], [{"cwe": "CWE-78"}])


def test_evaluate_case_requires_a_case():
    with pytest.raises(ValueError, match="BenchmarkCase"):
        evaluate_case("c1", [])


# -- evaluate over a benchmark -----------------------------------------------


def benchmark():
    return Benchmark(
        (
            case(exp("e1", line=10), exp("e2", cwe="CWE-89"), case_id="b"),
            case(exp("e1", file="x.py"), case_id="a"),
            case(case_id="empty", language=Language.C),
        )
    )


def test_missing_prediction_entries_are_rejected():
    with pytest.raises(ValueError, match="missing predictions.*'a'.*'empty'"):
        evaluate(benchmark(), {"b": []})


def test_unknown_prediction_entries_are_rejected():
    with pytest.raises(ValueError, match="unknown cases.*'nope'"):
        evaluate(benchmark(), {"a": [], "b": [], "empty": [], "nope": []})


def test_explicit_empty_sequences_are_valid():
    result = evaluate(benchmark(), {"a": [], "b": (), "empty": []})

    assert result.counts == Counts(0, 0, 3)


def test_predictions_must_be_a_mapping_with_string_keys():
    with pytest.raises(ValueError, match="mapping"):
        evaluate(benchmark(), [])

    with pytest.raises(ValueError, match="keys"):
        evaluate(Benchmark(), {1: []})

    with pytest.raises(ValueError, match="Benchmark"):
        evaluate({}, {})


def test_language_is_checked_per_case():
    with pytest.raises(ValueError, match="finding is"):
        evaluate(
            benchmark(),
            {"a": [], "b": [], "empty": [make_finding()]},  # python finding, C case
        )


def test_aggregate_counts_are_summed_before_ratios():
    result = evaluate(
        benchmark(),
        {
            "a": [finding(file="x.py")],  # tp 1
            "b": [finding(line=10), finding(cwe="CWE-79")],  # tp 1, fp 1, fn 1
            "empty": [],
        },
    )

    assert [c.case_id for c in result.cases] == ["a", "b", "empty"]
    assert result.counts == Counts(tp=2, fp=1, fn=1)
    assert result.precision == 2 / 3
    assert result.recall == 2 / 3
    assert result.f1 == 2 * 2 / (2 * 2 + 1 + 1)


def test_micro_metrics_differ_from_averaging_per_case_metrics():
    big = case(*(exp(f"e{i}") for i in range(9)), case_id="big")
    tiny = case(exp("e0"), case_id="tiny")
    result = evaluate(
        Benchmark((big, tiny)),
        {"big": [finding() for _ in range(9)], "tiny": []},
    )

    per_case_recall = [c.counts.recall for c in result.cases]

    assert per_case_recall == [1.0, 0.0]
    assert result.recall == 9 / 10
    assert result.recall != sum(per_case_recall) / 2


def test_empty_benchmark_gives_zero_metrics():
    result = evaluate(Benchmark(), {})

    assert result.counts == Counts()
    assert (result.precision, result.recall, result.f1) == (0.0, 0.0, 0.0)


def test_results_do_not_depend_on_prediction_key_order():
    predictions = {"a": [], "b": [finding(line=10)], "empty": []}
    reversed_predictions = dict(reversed(list(predictions.items())))

    assert evaluate(benchmark(), predictions) == evaluate(
        benchmark(), reversed_predictions
    )


def test_evaluation_result_rejects_duplicate_case_ids():
    one = run([], [])

    with pytest.raises(ValueError, match="duplicate"):
        EvaluationResult((one, one))


def test_results_are_immutable():
    result = run([exp("e")], [finding()])

    with pytest.raises(AttributeError):
        result.case_id = "x"

    with pytest.raises(AttributeError):
        evaluate(Benchmark(), {}).cases = ()


def test_no_true_negative_or_macro_members_exist():
    result = evaluate(Benchmark(), {})

    for name in ("tn", "true_negatives", "accuracy", "specificity", "macro_f1"):
        assert not hasattr(result, name)
        assert not hasattr(result.counts, name)


def test_inputs_are_not_modified():
    found = [finding(line=30), finding(line=1)]
    snapshot = list(found)
    run([exp("e", line=1)], found)

    assert found == snapshot


# -- immutable result collections -----------------------------------------


def test_result_collections_are_tuples():
    result = run([exp("e1"), exp("e2", cwe="CWE-89")], [finding(), finding(line=99)])

    assert isinstance(result.matches, tuple)
    assert isinstance(result.unmatched_expected, tuple)
    assert isinstance(result.unmatched_actual, tuple)
    assert isinstance(evaluate(Benchmark(), {}).cases, tuple)


def build_case_result(matches, unmatched_expected, unmatched_actual):
    from vulnsight.eval import CaseResult

    return CaseResult("c1", matches, unmatched_expected, unmatched_actual)


def test_case_result_copies_mutable_lists_into_tuples():
    from vulnsight.eval import Match

    match = Match(exp("e1"), finding())
    matches, missed, extra = [match], [exp("e2")], [finding(line=50)]
    result = build_case_result(matches, missed, extra)

    matches.append(match)
    missed.clear()
    extra.append(finding(line=60))

    assert result.matches == (match,)
    assert len(result.unmatched_expected) == 1
    assert len(result.unmatched_actual) == 1
    assert result.counts == Counts(1, 1, 1)
    for name in ("matches", "unmatched_expected", "unmatched_actual"):
        assert isinstance(getattr(result, name), tuple)


def test_evaluation_result_copies_a_mutable_list_into_a_tuple():
    first, second = (
        run(
            [],
            [],
        ),
        evaluate_case(case(case_id="c2"), []),
    )
    cases = [first, second]
    result = EvaluationResult(cases)

    cases.clear()

    assert result.cases == (first, second)
    assert isinstance(result.cases, tuple)
    assert result.counts == Counts()


def test_evaluate_results_do_not_alias_the_callers_prediction_list():
    found = [finding()]
    result = run([exp("e1")], found)

    found.clear()
    found.append(finding(line=99))

    assert result.matches[0].finding.location.line == 10
    assert result.counts == Counts(1, 0, 0)


@pytest.mark.parametrize("bad", ["abc", b"abc", None, 5])
def test_case_result_collections_must_be_sequences(bad):
    for position in range(3):
        arguments = [(), (), ()]
        arguments[position] = bad

        with pytest.raises(ValueError, match="must be a sequence"):
            build_case_result(*arguments)


def test_case_result_validates_element_types():
    from vulnsight.eval import Match

    match = Match(exp("e1"), finding())

    with pytest.raises(ValueError, match="matches must hold Match"):
        build_case_result((exp("e1"),), (), ())

    with pytest.raises(ValueError, match="unmatched_expected must hold Expected"):
        build_case_result((), (finding(),), ())

    with pytest.raises(ValueError, match="unmatched_actual must hold Finding"):
        build_case_result((), (), (exp("e1"),))

    with pytest.raises(ValueError, match="matches must hold Match"):
        build_case_result((match, "x"), (), ())


def test_case_result_requires_a_case_id():
    from vulnsight.eval import CaseResult

    for bad in ("", None, 3):
        with pytest.raises(ValueError, match="case_id"):
            CaseResult(bad, (), (), ())


def test_evaluation_result_validates_collection_and_elements():
    for bad in ("abc", None, 5):
        with pytest.raises(ValueError, match="must be a sequence"):
            EvaluationResult(bad)

    with pytest.raises(ValueError, match="cases must hold CaseResult"):
        EvaluationResult(("c1",))

    with pytest.raises(ValueError, match="cases must hold CaseResult"):
        EvaluationResult([run([], []), None])


def test_match_validates_its_members():
    from vulnsight.eval import Match

    with pytest.raises(ValueError, match="ExpectedFinding"):
        Match("e1", finding())

    with pytest.raises(ValueError, match="Finding"):
        Match(exp("e1"), {"cwe": "CWE-78"})

    assert Match(exp("e1"), finding()).expected_id == "e1"


def test_hand_built_results_still_compare_equal_to_evaluated_ones():
    from vulnsight.eval import CaseResult, Match

    only = finding()
    built = CaseResult("c1", [Match(exp("e1"), only)], [], [])

    assert built == run([exp("e1")], [only])


# -- canonical ordering of result collections --------------------------------


def evaluated_sample():
    """An evaluated case with several matches and several unmatched items."""

    items = [
        exp("z-both", file="a.py", line=10),
        exp("m-file", file="a.py"),
        exp("a-loose"),
        exp("q-miss", cwe="CWE-89"),
        exp("b-miss", cwe="CWE-22"),
    ]
    found = [
        finding(file="a.py", line=10),
        finding(file="a.py", line=11),
        finding(file="b.py", line=70),
        finding(cwe="CWE-79", line=3),
        finding(cwe="CWE-79", line=1),
    ]

    return run(items, found)


def rebuilt(result, rng):
    """Rebuild a result from shuffled copies of its collections."""

    from vulnsight.eval import CaseResult

    parts = [
        list(result.matches),
        list(result.unmatched_expected),
        list(result.unmatched_actual),
    ]

    for part in parts:
        rng.shuffle(part)

    return CaseResult(result.case_id, *parts)


def test_matches_follow_the_canonical_order_of_the_matched_expected_finding():
    from vulnsight.eval.metrics import _expected_order

    result = evaluated_sample()
    keys = [_expected_order(match.expected) for match in result.matches]

    assert len(keys) >= 3
    assert keys == sorted(keys)
    # Specific expectations come first, so the order is not by expected_id.
    assert [m.expected_id for m in result.matches] != sorted(
        m.expected_id for m in result.matches
    )


def test_unmatched_collections_are_ordered_by_id_and_canonical_finding_order():
    result = evaluated_sample()
    ids = [item.expected_id for item in result.unmatched_expected]

    assert ids == sorted(ids) and len(ids) == 2
    # The CWE-78 finding at b.py:70 is matched by the loose expectation, so the
    # two CWE-79 findings are left, in line order.
    assert [f.location.line for f in result.unmatched_actual] == [1, 3]


def test_manually_built_results_with_shuffled_collections_equal_evaluated_ones():
    result = evaluated_sample()
    rng = random.Random(99)

    for _ in range(50):
        assert rebuilt(result, rng) == result


def test_manual_construction_orders_every_collection_canonically():
    from vulnsight.eval import CaseResult, Match

    one, two = Match(exp("b"), finding(line=1)), Match(exp("a"), finding(line=2))
    late, early = finding(line=40), finding(line=2)
    zed, aye = exp("zed"), exp("aye", cwe="CWE-89")

    built = CaseResult("c1", [one, two], [zed, aye], [late, early])

    assert [m.expected_id for m in built.matches] == ["a", "b"]
    assert [e.expected_id for e in built.unmatched_expected] == ["aye", "zed"]
    assert built.unmatched_actual == (early, late)
    assert built == CaseResult("c1", (two, one), (aye, zed), (early, late))


def test_matches_with_equal_expected_findings_are_ordered_by_their_findings():
    from vulnsight.eval import CaseResult, Match

    one, two = finding(line=30), finding(line=4)
    first = CaseResult("c", [Match(exp("e"), one), Match(exp("e"), two)], (), ())
    second = CaseResult("c", [Match(exp("e"), two), Match(exp("e"), one)], (), ())

    assert first == second
    assert [m.finding.location.line for m in first.matches] == [4, 30]


def test_evaluation_result_cases_are_always_ordered_by_case_id():
    cases = [evaluate_case(case(case_id=name), []) for name in ("b", "c", "a")]

    for ordering in itertools.permutations(cases):
        result = EvaluationResult(list(ordering))

        assert [c.case_id for c in result.cases] == ["a", "b", "c"]
        assert result == EvaluationResult(tuple(cases))

    assert isinstance(EvaluationResult(cases).cases, tuple)


def test_manual_evaluation_result_equals_the_evaluated_one():
    benchmark_ = benchmark()
    predictions = {"a": [finding(file="x.py")], "b": [finding(line=10)], "empty": []}
    evaluated = evaluate(benchmark_, predictions)
    manual = EvaluationResult(
        [evaluate_case(benchmark_.case(i), predictions[i]) for i in ("empty", "b", "a")]
    )

    assert manual == evaluated
    assert manual.counts == evaluated.counts


@pytest.mark.parametrize(
    "unordered",
    [
        {1},
        frozenset({1}),
        {"a": 1},
        {"a": 1}.keys(),
        {"a": 1}.values(),
        iter([]),
        (x for x in ()),
    ],
)
def test_unordered_collections_are_rejected(unordered):
    from vulnsight.eval import CaseResult

    for position in range(3):
        arguments = [(), (), ()]
        arguments[position] = unordered

        with pytest.raises(ValueError, match="must be a sequence"):
            CaseResult("c1", *arguments)

    with pytest.raises(ValueError, match="must be a sequence"):
        EvaluationResult(unordered)


def test_sets_of_real_result_objects_are_rejected():
    from vulnsight.eval import CaseResult, Match

    match = Match(exp("e"), finding())

    with pytest.raises(ValueError, match="matches must be a sequence"):
        CaseResult("c1", {match}, (), ())

    with pytest.raises(ValueError, match="unmatched_expected must be a sequence"):
        CaseResult("c1", (), {exp("e")}, ())

    with pytest.raises(ValueError, match="unmatched_actual must be a sequence"):
        CaseResult("c1", (), (), frozenset({finding()}))

    with pytest.raises(ValueError, match="cases must be a sequence"):
        EvaluationResult({evaluate_case(case(), [])})


def test_tuple_immutability_survives_canonical_ordering():
    from vulnsight.eval import CaseResult

    source = [finding(line=9), finding(line=1)]
    built = CaseResult("c1", [], [], source)
    source.reverse()
    source.append(finding(line=5))

    assert isinstance(built.unmatched_actual, tuple)
    assert [f.location.line for f in built.unmatched_actual] == [1, 9]

    with pytest.raises(AttributeError):
        built.unmatched_actual = ()

    with pytest.raises(TypeError):
        built.unmatched_actual[0] = finding()
