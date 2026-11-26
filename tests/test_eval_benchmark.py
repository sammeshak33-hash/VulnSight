"""Tests for the benchmark models and their JSON form."""

import json

import pytest

from vulnsight.eval import (
    BENCHMARK_SCHEMA_VERSION,
    Benchmark,
    BenchmarkCase,
    ExpectedFinding,
)
from vulnsight.findings import Language


def expected(expected_id="e1", cwe="CWE-78", file=None, line=None):
    return ExpectedFinding(expected_id, cwe, file, line)


def case(case_id="c1", language=Language.PYTHON, findings=()):
    return BenchmarkCase(case_id, language, tuple(findings))


# -- ExpectedFinding ---------------------------------------------------


def test_expected_finding_defaults_leave_location_unspecified():
    item = ExpectedFinding("e1", "CWE-78")

    assert item.file is None
    assert item.line is None
    assert item.specificity == 0


@pytest.mark.parametrize(
    ("file", "line", "specificity"),
    [(None, None, 0), ("a.py", None, 1), (None, 3, 1), ("a.py", 3, 2)],
)
def test_specificity_counts_specified_location_parts(file, line, specificity):
    assert expected(file=file, line=line).specificity == specificity


def test_file_is_normalized_but_case_is_kept():
    assert expected(file="src\\App.py").file == "src/App.py"


@pytest.mark.parametrize(
    "bad", ["", "cwe-78", "CWE-", "CWE-7a", "78", "CWE-78 ", None, 78]
)
def test_cwe_format_is_checked(bad):
    with pytest.raises(ValueError, match="cwe"):
        expected(cwe=bad)


@pytest.mark.parametrize("bad", ["", None, 3, b"x"])
def test_expected_id_must_be_non_empty_text(bad):
    with pytest.raises(ValueError, match="expected_id"):
        expected(expected_id=bad)


@pytest.mark.parametrize("bad", [0, -1, True, False, 1.0, "3"])
def test_line_must_be_a_positive_integer_and_not_a_bool(bad):
    with pytest.raises(ValueError, match="line"):
        expected(line=bad)


@pytest.mark.parametrize("bad", ["", 5, b"a.py"])
def test_file_must_be_non_empty_text_when_given(bad):
    with pytest.raises(ValueError):
        expected(file=bad)


def test_expected_finding_is_immutable():
    with pytest.raises(AttributeError):
        expected().line = 3


# -- BenchmarkCase -------------------------------------------------------


def test_case_requires_a_language_enum():
    with pytest.raises(ValueError, match="language"):
        BenchmarkCase("c1", "python", ())


def test_case_accepts_every_existing_language():
    for language in Language:
        assert case(language=language).language is language


@pytest.mark.parametrize("bad", ["", None, 1])
def test_case_id_must_be_non_empty_text(bad):
    with pytest.raises(ValueError, match="case_id"):
        case(case_id=bad)


def test_empty_expected_findings_are_valid():
    assert case().expected_findings == ()


def test_duplicate_expected_ids_in_a_case_are_rejected():
    with pytest.raises(ValueError, match="duplicate expected_id.*'e1'"):
        case(findings=[expected("e1"), expected("e1", cwe="CWE-79")])


def test_same_expected_id_in_different_cases_is_allowed():
    Benchmark(
        (case("a", findings=[expected("e1")]), case("b", findings=[expected("e1")]))
    )


def test_expected_findings_are_a_tuple_sorted_by_id():
    built = case(findings=[expected("b"), expected("a"), expected("c")])

    assert isinstance(built.expected_findings, tuple)
    assert [e.expected_id for e in built.expected_findings] == ["a", "b", "c"]


def test_expected_findings_must_hold_expected_findings():
    with pytest.raises(ValueError, match="ExpectedFinding"):
        BenchmarkCase("c1", Language.PYTHON, ("e1",))

    with pytest.raises(ValueError, match="sequence"):
        BenchmarkCase("c1", Language.PYTHON, "abc")

    with pytest.raises(ValueError, match="sequence"):
        BenchmarkCase("c1", Language.PYTHON, 5)


def test_case_cannot_be_changed_and_mutating_the_source_list_has_no_effect():
    source = [expected("a")]
    built = case(findings=source)
    source.append(expected("b"))

    assert len(built.expected_findings) == 1

    with pytest.raises(AttributeError):
        built.case_id = "x"


# -- Benchmark -----------------------------------------------------------


def test_duplicate_case_ids_are_rejected():
    with pytest.raises(ValueError, match="duplicate case_id.*'c1'"):
        Benchmark((case("c1"), case("c1", Language.C)))


def test_cases_are_sorted_by_id_and_order_does_not_matter():
    one = Benchmark((case("b"), case("a")))
    two = Benchmark((case("a"), case("b")))

    assert [c.case_id for c in one.cases] == ["a", "b"]
    assert one == two
    assert one.to_json() == two.to_json()


def test_benchmark_must_hold_cases():
    with pytest.raises(ValueError, match="BenchmarkCase"):
        Benchmark(("c1",))

    with pytest.raises(ValueError, match="sequence"):
        Benchmark("c1")


def test_empty_benchmark_is_valid():
    assert Benchmark().cases == ()


def test_case_lookup():
    benchmark = Benchmark((case("a"), case("b")))

    assert benchmark.case("b").case_id == "b"

    with pytest.raises(KeyError):
        benchmark.case("zzz")


# -- JSON ---------------------------------------------------------------


def sample():
    return Benchmark(
        (
            case(
                "py-1",
                findings=[
                    expected("e2", file="src\\a.py", line=7),
                    expected("e1", cwe="CWE-89"),
                ],
            ),
            case("c-1", Language.C, [expected("x", cwe="CWE-120", line=3)]),
            case("empty", Language.CPP),
        )
    )


def test_round_trip_is_exact():
    benchmark = sample()

    assert Benchmark.from_json(benchmark.to_json()) == benchmark


def test_json_is_deterministic_and_has_no_trailing_newline():
    text = sample().to_json()

    assert text == sample().to_json()
    assert not text.endswith("\n")
    assert "\r" not in text
    assert json.loads(text)["schema_version"] == BENCHMARK_SCHEMA_VERSION == "1.0"


def test_json_uses_sorted_keys_forward_slashes_and_explicit_nulls():
    data = json.loads(sample().to_json())

    assert list(data) == sorted(data)
    first = data["cases"][0]
    assert first["case_id"] == "c-1"
    assert first["language"] == "c"
    assert first["expected_findings"][0] == {
        "cwe": "CWE-120",
        "expected_id": "x",
        "file": None,
        "line": 3,
    }
    assert data["cases"][2]["expected_findings"][1]["file"] == "src/a.py"


def test_json_is_ascii_only():
    benchmark = Benchmark((case("café", findings=[expected(file="é/ü.py")]),))
    text = benchmark.to_json()

    assert text.isascii()
    assert Benchmark.from_json(text) == benchmark


def test_json_input_order_does_not_change_the_result():
    data = sample().to_dict()
    data["cases"].reverse()

    assert Benchmark.from_json(json.dumps(data)) == sample()


def test_optional_keys_may_be_absent_on_input():
    text = json.dumps(
        {
            "schema_version": "1.0",
            "cases": [
                {
                    "case_id": "c",
                    "language": "python",
                    "expected_findings": [{"expected_id": "e", "cwe": "CWE-78"}],
                }
            ],
        }
    )

    item = Benchmark.from_json(text).cases[0].expected_findings[0]

    assert (item.file, item.line) == (None, None)


def mutated(change):
    data = sample().to_dict()
    change(data)

    return json.dumps(data)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schema_version="2.0"),
        lambda d: d.update(schema_version=1),
        lambda d: d.pop("schema_version"),
        lambda d: d.pop("cases"),
        lambda d: d.update(extra=1),
        lambda d: d.update(cases={}),
        lambda d: d["cases"][0].update(language="java"),
        lambda d: d["cases"][0].update(language=3),
        lambda d: d["cases"][0].update(extra=1),
        lambda d: d["cases"][0].pop("case_id"),
        lambda d: d["cases"][0].update(expected_findings="x"),
        lambda d: d["cases"][0].update(case_id=""),
        lambda d: d["cases"][0]["expected_findings"][0].update(line=True),
        lambda d: d["cases"][0]["expected_findings"][0].update(line=0),
        lambda d: d["cases"][0]["expected_findings"][0].update(line=1.5),
        lambda d: d["cases"][0]["expected_findings"][0].update(cwe="78"),
        lambda d: d["cases"][0]["expected_findings"][0].update(file=""),
        lambda d: d["cases"][0]["expected_findings"][0].update(file=5),
        lambda d: d["cases"][0]["expected_findings"][0].update(extra=1),
        lambda d: d["cases"][0]["expected_findings"][0].pop("expected_id"),
        lambda d: d["cases"][0]["expected_findings"].append(
            dict(d["cases"][0]["expected_findings"][0])
        ),
        lambda d: d["cases"].append(dict(d["cases"][0])),
        lambda d: d["cases"].append("x"),
    ],
)
def test_malformed_documents_are_rejected(change):
    with pytest.raises(ValueError):
        Benchmark.from_json(mutated(change))


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        "[]",
        "null",
        '{"schema_version": "1.0", "cases": [], "cases": []}',
        '{"schema_version": "1.0", "cases": [NaN]}',
        '{"schema_version": "1.0", "cases": [Infinity]}',
        "[" * 100000,
    ],
)
def test_bad_json_text_is_rejected(text):
    with pytest.raises(ValueError):
        Benchmark.from_json(text)


@pytest.mark.parametrize("bad", [None, 5, b"{}"])
def test_json_input_must_be_text(bad):
    with pytest.raises(ValueError, match="string"):
        Benchmark.from_json(bad)


def test_duplicate_expected_ids_in_json_are_rejected_with_the_id():
    def duplicate(d):
        entry = d["cases"][0]["expected_findings"]
        entry.append(dict(entry[0]))

    with pytest.raises(ValueError, match="duplicate expected_id"):
        Benchmark.from_json(mutated(duplicate))


def test_windows_style_paths_in_json_are_normalized():
    data = sample().to_dict()
    data["cases"][2]["expected_findings"][1]["file"] = "dir\\Sub\\a.py"

    result = Benchmark.from_json(json.dumps(data))

    assert result.case("py-1").expected_findings[1].file == "dir/Sub/a.py"


# -- from_dict with non-string keys ------------------------------------


@pytest.mark.parametrize("key", [1, None, 2.5, (1, 2), True])
def test_from_dict_rejects_non_string_keys_at_every_level(key):
    good = sample().to_dict()

    top = dict(good)
    top[key] = 1
    case_level = sample().to_dict()
    case_level["cases"][0][key] = 1
    item_level = sample().to_dict()
    item_level["cases"][0]["expected_findings"][0][key] = 1

    for data in (top, case_level, item_level):
        with pytest.raises(ValueError, match="keys must be strings"):
            Benchmark.from_dict(data)


def test_from_dict_rejects_non_dictionary_values():
    for data in (None, [], "x", 3):
        with pytest.raises(ValueError, match="must be an object"):
            Benchmark.from_dict(data)


def test_from_dict_round_trips_to_dict():
    assert Benchmark.from_dict(sample().to_dict()) == sample()
