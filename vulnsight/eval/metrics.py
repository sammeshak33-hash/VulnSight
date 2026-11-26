"""Evaluation core: match findings to expectations and count TP, FP and FN.

Scope
-----
* The input is a ``Benchmark`` and, per case, a sequence of ``Finding`` values.
  ``ScanResult`` is not used. The caller must only evaluate **completed**
  scans: a failed or partial scan has missing findings, and scoring it would
  report false negatives that are really scan errors.
* There is no true-negative count and there are no macro averages. No
  negative universe is defined, so TN, accuracy and specificity would be
  invented numbers.

Matching
--------
An expected finding and an actual finding are compatible when:

* the CWE is exactly equal;
* the file is equal, if the expected finding names one (exact, case-sensitive
  comparison after ``/`` normalization; an actual finding without a file never
  matches an expected file);
* the actual starting line differs from the expected line by at most
  ``LINE_TOLERANCE``, if the expected finding names a line.

An unspecified file or line puts no constraint on matching. Columns, rule IDs,
confidence and every other field are ignored. ``finding_id`` and
``fingerprint`` are never used.

The matching is one-to-one and has maximum cardinality (the most pairs
possible). Among such matchings, the set of matched expected findings prefers
the more specific ones (more location parts specified), then follows the
canonical order. Line distance is never optimized: among compatible actual
findings the first one in canonical order is taken, unless an alternating path
is needed to keep the matching maximal. Input order is never used.
"""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from vulnsight.eval.benchmark import Benchmark, BenchmarkCase, ExpectedFinding
from vulnsight.findings import Finding, require_integer, require_text

LINE_TOLERANCE = 5

# Derived identifiers are never used. Every other field takes part in the
# canonical order, so only findings with identical content can tie.
_IDENTITY_FIELDS = ("fingerprint", "finding_id")


@dataclass(frozen=True)
class Counts:
    """True positives, false positives and false negatives."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    def __post_init__(self):
        require_integer("tp", self.tp, 0)
        require_integer("fp", self.fp, 0)
        require_integer("fn", self.fn, 0)

    def __add__(self, other: "Counts") -> "Counts":
        if not isinstance(other, Counts):
            return NotImplemented

        return Counts(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    @property
    def precision(self) -> float:
        """TP / (TP + FP), or 0.0 when there are no predictions."""

        denominator = self.tp + self.fp

        return self.tp / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN), or 0.0 when nothing was expected."""

        denominator = self.tp + self.fn

        return self.tp / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        """2TP / (2TP + FP + FN), the harmonic mean, or 0.0 when undefined."""

        denominator = 2 * self.tp + self.fp + self.fn

        return 2 * self.tp / denominator if denominator else 0.0


@dataclass(frozen=True)
class Match:
    """An expected finding paired with the actual finding that matched it."""

    expected: ExpectedFinding
    finding: Finding

    def __post_init__(self):
        if not isinstance(self.expected, ExpectedFinding):
            raise ValueError("expected must be an ExpectedFinding")

        if not isinstance(self.finding, Finding):
            raise ValueError("finding must be a Finding")

    @property
    def expected_id(self) -> str:
        return self.expected.expected_id


@dataclass(frozen=True)
class CaseResult:
    """The outcome for one case.

    The collections are stored as tuples in a canonical order that is enforced
    on construction, so a hand-built result equals an evaluated one whatever
    order its inputs came in: ``matches`` follow the canonical order of the
    matched expected finding, ``unmatched_expected`` is ordered by
    ``expected_id`` and ``unmatched_actual`` follows the canonical finding
    order. Duplicate actual findings stay separate entries.
    """

    case_id: str
    matches: tuple[Match, ...]
    unmatched_expected: tuple[ExpectedFinding, ...]
    unmatched_actual: tuple[Finding, ...]

    def __post_init__(self):
        require_text("case_id", self.case_id)
        _store(self, "matches", Match, _match_order)
        _store(
            self,
            "unmatched_expected",
            ExpectedFinding,
            lambda item: item.expected_id,
        )
        _store(self, "unmatched_actual", Finding, _finding_order)

    @property
    def counts(self) -> Counts:
        return Counts(
            tp=len(self.matches),
            fp=len(self.unmatched_actual),
            fn=len(self.unmatched_expected),
        )


@dataclass(frozen=True)
class EvaluationResult:
    """Per-case results (always ordered by ``case_id``) and micro totals."""

    cases: tuple[CaseResult, ...]

    def __post_init__(self):
        _store(self, "cases", CaseResult, lambda case: case.case_id)
        ids = [case.case_id for case in self.cases]

        if len(set(ids)) != len(ids):
            raise ValueError("duplicate case_id in results")

    @property
    def counts(self) -> Counts:
        """Counts summed over all cases, before any ratio is computed."""

        total = Counts()

        for case in self.cases:
            total = total + case.counts

        return total

    @property
    def precision(self) -> float:
        return self.counts.precision

    @property
    def recall(self) -> float:
        return self.counts.recall

    @property
    def f1(self) -> float:
        return self.counts.f1


def _store(owner, name: str, kind: type, order) -> None:
    """Replace a field by a sorted tuple of ``kind`` values.

    Only ordered sequences (a list or a tuple, not a string) are accepted. Sets,
    dictionaries, views and iterators are rejected, so an arbitrary iteration
    order can never enter a result. A list is copied. The items are then sorted
    by ``order``, so every result has one canonical form.
    """

    value = getattr(owner, name)

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} must be a sequence")

    items = tuple(value)

    for item in items:
        if not isinstance(item, kind):
            raise ValueError(f"{name} must hold {kind.__name__} values")

    object.__setattr__(owner, name, tuple(sorted(items, key=order)))


def _match_order(match: Match):
    return (_expected_order(match.expected), _finding_order(match.finding))


# -- matching ------------------------------------------------------


def is_compatible(expected: ExpectedFinding, finding: Finding) -> bool:
    """Apply the matching rules to one pair."""

    if expected.cwe != finding.cwe:
        return False

    if expected.file is not None and expected.file != finding.location.file:
        return False

    if (
        expected.line is not None
        and abs(finding.location.line - expected.line) > LINE_TOLERANCE
    ):
        return False

    return True


def _expected_order(expected: ExpectedFinding):
    return (
        -expected.specificity,
        expected.cwe,
        expected.file is not None,
        expected.file or "",
        expected.line is not None,
        expected.line or 0,
        expected.expected_id,
    )


def _finding_order(finding: Finding):
    """Total order on finding content. Ignores identity fields and input order."""

    location = finding.location
    content = finding.to_dict()

    for name in _IDENTITY_FIELDS:
        del content[name]

    return (
        finding.cwe,
        location.file is not None,
        location.file or "",
        location.line,
        location.column,
        -1 if location.end_line is None else location.end_line,
        -1 if location.end_column is None else location.end_column,
        finding.rule_id,
        json.dumps(content, sort_keys=True, ensure_ascii=True, allow_nan=False),
    )


def _match(expected: Sequence[ExpectedFinding], actual: Sequence[Finding]):
    """Return ``{expected index: actual index}`` for both pre-sorted inputs."""

    adjacency = [
        [j for j, finding in enumerate(actual) if is_compatible(item, finding)]
        for item in expected
    ]
    partner_of_expected: dict[int, int] = {}
    partner_of_actual: dict[int, int] = {}

    for start in range(len(expected)):
        previous: dict[int, int] = {}
        queue = [start]

        for current in queue:
            found = None

            for candidate in adjacency[current]:
                if candidate in previous:
                    continue

                previous[candidate] = current
                holder = partner_of_actual.get(candidate)

                if holder is None:
                    found = candidate
                    break

                queue.append(holder)

            if found is not None:
                # Flip the alternating path back to ``start``.
                target = found

                while True:
                    owner = previous[target]
                    earlier = partner_of_expected.get(owner)
                    partner_of_expected[owner] = target
                    partner_of_actual[target] = owner

                    if owner == start:
                        break

                    target = earlier

                break

    return partner_of_expected


def evaluate_case(case: BenchmarkCase, findings: Sequence[Finding]) -> CaseResult:
    """Match one case's findings against its expectations."""

    if not isinstance(case, BenchmarkCase):
        raise ValueError("case must be a BenchmarkCase")

    actual = _check_findings(case, findings)
    expected = sorted(case.expected_findings, key=_expected_order)
    actual = sorted(actual, key=_finding_order)
    pairs = _match(expected, actual)

    matched_actual = set(pairs.values())

    return CaseResult(
        case_id=case.case_id,
        matches=tuple(Match(expected[i], actual[j]) for i, j in pairs.items()),
        unmatched_expected=tuple(
            item for i, item in enumerate(expected) if i not in pairs
        ),
        unmatched_actual=tuple(
            finding for j, finding in enumerate(actual) if j not in matched_actual
        ),
    )


def evaluate(
    benchmark: Benchmark, predictions: Mapping[str, Sequence[Finding]]
) -> EvaluationResult:
    """Evaluate every case of ``benchmark``.

    ``predictions`` maps each ``case_id`` to its findings. Every case needs an
    entry (an empty sequence is valid, and means nothing was reported) and no
    entry may name an unknown case.
    """

    if not isinstance(benchmark, Benchmark):
        raise ValueError("benchmark must be a Benchmark")

    if not isinstance(predictions, Mapping):
        raise ValueError("predictions must be a mapping of case_id to findings")

    for key in predictions:
        if not isinstance(key, str):
            raise ValueError("prediction keys must be case_id strings")

    known = {case.case_id for case in benchmark.cases}
    missing = sorted(known - predictions.keys())
    unknown = sorted(predictions.keys() - known)

    if missing:
        raise ValueError(
            "missing predictions for cases: " + ", ".join(repr(i) for i in missing)
        )

    if unknown:
        raise ValueError(
            "predictions for unknown cases: " + ", ".join(repr(i) for i in unknown)
        )

    return EvaluationResult(
        tuple(
            evaluate_case(case, predictions[case.case_id]) for case in benchmark.cases
        )
    )


def _check_findings(case: BenchmarkCase, findings) -> list[Finding]:
    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence):
        raise ValueError(f"predictions for case {case.case_id!r} must be a sequence")

    for finding in findings:
        if not isinstance(finding, Finding):
            raise ValueError(
                f"predictions for case {case.case_id!r} must hold Finding values"
            )

        if finding.language != case.language:
            raise ValueError(
                f"case {case.case_id!r} is {case.language.value} but a finding is "
                f"{finding.language.value}"
            )

    return list(findings)
