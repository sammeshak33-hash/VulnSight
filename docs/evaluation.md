# Evaluation foundation (M2.1)

`vulnsight.eval` scores findings against a benchmark of expected findings. It is deterministic, immutable and has no dependencies. It does not run scanners, read datasets or print reports: the micro-benchmark and the `eval` command are M2.2, and the Bandit and Semgrep adapters are M2.3.

```python
from vulnsight.eval import Benchmark, BenchmarkCase, ExpectedFinding, evaluate
from vulnsight.findings import Language

benchmark = Benchmark(
    (
        BenchmarkCase(
            "cmd-001",
            Language.PYTHON,
            (ExpectedFinding("e1", "CWE-78", file="app.py", line=12),),
        ),
    )
)
result = evaluate(benchmark, {"cmd-001": findings})  # findings: a sequence of Finding
result.counts, result.precision, result.recall, result.f1
```

## Who may call it

Evaluation takes `Finding` sequences, never a `ScanResult`. **The caller must only evaluate completed scans.** A `partial` or `failed` scan is missing findings, and scoring it would report scan errors as false negatives (and a failed scan with no findings would look like a clean one). Checking `ScanResult.status` is the caller's job.

## Models (`vulnsight.eval.benchmark`)

| Type | Fields |
|---|---|
| `ExpectedFinding` | `expected_id`, `cwe` (`CWE-<digits>`), optional `file`, optional `line` (integer ≥ 1, never a bool) |
| `BenchmarkCase` | `case_id`, `language` (the existing `Language` enum), `expected_findings` (a tuple, sorted by `expected_id`) |
| `Benchmark` | `cases` (a tuple, sorted by `case_id`) |

`None` for `file` or `line` means *not specified*: it puts no constraint on matching. It never means "no file" or "no line". Files are normalized to `/`; case is kept. An empty `expected_findings` is valid (nothing should be reported). Duplicate `expected_id` values in a case and duplicate `case_id` values in a benchmark are rejected. Models are frozen, and input order never matters.

### JSON

`Benchmark.to_json()` and `Benchmark.from_json(text)` use the standard library only. The format is `{"schema_version": "1.0", "cases": [...]}` with sorted keys, 2-space indent, ASCII only, no trailing newline, and explicit `null` for unspecified `file` and `line` (they may be absent on input). Parsing is strict: duplicate keys, `NaN`, `Infinity`, unknown or missing keys, wrong types, booleans as lines, and other schema versions are rejected with `ValueError`. This schema is separate from the `ScanResult` schema; the codec and the Finding schema are unchanged. Evaluation results have no JSON form in M2.1.

## Matching (`vulnsight.eval.metrics`)

An expected and an actual finding are compatible when all of these hold:

- the CWE is equal;
- the file is equal, if the expected finding names one (exact, case-sensitive; an actual finding with no file never matches a named file);
- the actual starting line differs from the expected line by at most `LINE_TOLERANCE = 5`, if the expected finding names a line. The end line and columns are not used.

Nothing else is compared. `finding_id` and `fingerprint` are never used, and there is no CWE filter or hierarchy.

The matching is **one-to-one with maximum cardinality**: no other matching has more pairs. Among such matchings, expected findings with more specified location parts (file and line, so 0, 1 or 2) get priority, then the canonical order (CWE, file, line, `expected_id`) decides. In practice: an expectation that names file and line wins a contested finding over a loose one, yet never at the price of fewer matches. Line distance is not optimized: an actual finding is paired with the first compatible one in canonical order, unless an alternating path is needed to keep the matching maximal.

Actual findings are sorted by a total order over their content (CWE, file, line, columns, `rule_id`, then the remaining fields as canonical JSON, excluding `finding_id` and `fingerprint`). Input indices are never used, so any permutation of the inputs gives an equal result. Only content-identical findings tie, and those are interchangeable. Duplicate actual findings are kept: each unmatched one is a false positive.

## Metrics

- **TP** = matched pairs, **FP** = unmatched actual findings, **FN** = unmatched expected findings.
- `precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`, `f1 = 2TP / (2TP + FP + FN)`.
- A zero denominator gives `0.0`. That makes "undefined" look like "zero": a case with no expectations has recall `0.0`. Read the counts next to the ratios.
- Aggregation is **micro**: counts are summed over cases, then ratios are computed. Macro averages are not provided.
- There is no TN, accuracy or specificity, because no negative universe is defined.

Result types are frozen, and their collections have one canonical order that is **enforced on construction**, so a result built by hand equals the one `evaluate()` returns, whatever order its inputs came in:

- `CaseResult.matches`: by the canonical key of the matched expected finding (more specific first, then CWE, file, line and `expected_id`), then by the matched finding's canonical order.
- `CaseResult.unmatched_expected`: by `expected_id`.
- `CaseResult.unmatched_actual`: by the canonical finding order described above.
- `EvaluationResult.cases`: by `case_id`.

Only ordered sequences (a list or a tuple) are accepted. Sets, dictionaries, dictionary views and iterators are rejected with `ValueError`, so an arbitrary iteration order can never enter a result. Collections are stored as tuples (a list passed in is copied) and their element types are validated, so later changes to the caller's lists cannot alter a stored result. `Benchmark.from_dict()` also rejects dictionaries with non-string keys.

`evaluate_case(case, findings)` returns a `CaseResult` with `matches` (each `Match` has the `ExpectedFinding` and the `Finding`, and `expected_id`), `unmatched_expected`, `unmatched_actual` and `counts`. `evaluate(benchmark, predictions)` returns an `EvaluationResult` with `cases` (sorted by `case_id`), `counts`, `precision`, `recall` and `f1`.

## Input checks

`evaluate` raises `ValueError` for: a prediction mapping that lacks a case, or names an unknown case; a non-mapping; a non-string key; a prediction that is not a sequence of `Finding` values; and a finding whose language differs from the case language. An explicit empty sequence is valid. Integer counts reject booleans.

## Limits

- Matching is by starting line within a fixed tolerance; there is no column or span matching.
- Only exact CWE equality counts, so a parent or child CWE does not match.
- The tolerance is a module constant, not a parameter.
