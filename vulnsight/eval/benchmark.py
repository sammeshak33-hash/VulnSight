"""Benchmark models: what a scanner is expected to find.

A benchmark is a set of cases. Each case has a language and the findings a
scanner is expected to report for it. Everything here is immutable and
validated when it is built. Nothing here runs a scanner or reads a dataset.

The JSON form is deterministic: the same benchmark always gives the same text.
"""

import json
import re
from dataclasses import dataclass
from typing import Any

from vulnsight.findings import (
    Language,
    normalize_path,
    require_integer,
    require_text,
)

BENCHMARK_SCHEMA_VERSION = "1.0"

_CWE_PATTERN = re.compile(r"CWE-[0-9]+")


@dataclass(frozen=True)
class ExpectedFinding:
    """One finding a scanner should report.

    ``file`` and ``line`` are optional. ``None`` means "not specified": it puts
    no constraint on matching. It never means "no file" or "no line".
    """

    expected_id: str
    cwe: str
    file: str | None = None
    line: int | None = None

    def __post_init__(self):
        require_text("expected_id", self.expected_id)

        if not isinstance(self.cwe, str) or not _CWE_PATTERN.fullmatch(self.cwe):
            raise ValueError("cwe must look like 'CWE-78'")

        if self.file is not None:
            object.__setattr__(self, "file", normalize_path(self.file))

        if self.line is not None:
            require_integer("line", self.line, 1)

    @property
    def specificity(self) -> int:
        """How many location parts are specified: 0, 1 (file or line) or 2."""

        return (self.file is not None) + (self.line is not None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_id": self.expected_id,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, data: Any, path: str = "expected_finding"):
        fields = _object(data, path, {"expected_id", "cwe"}, {"file", "line"})

        return cls(
            expected_id=fields["expected_id"],
            cwe=fields["cwe"],
            file=fields.get("file"),
            line=fields.get("line"),
        )


@dataclass(frozen=True)
class BenchmarkCase:
    """A language and the findings expected for it.

    ``expected_findings`` is stored as a tuple sorted by ``expected_id``, so the
    order given by the caller does not matter. An empty tuple is valid: it
    describes code where nothing should be reported.
    """

    case_id: str
    language: Language
    expected_findings: tuple[ExpectedFinding, ...] = ()

    def __post_init__(self):
        require_text("case_id", self.case_id)

        if not isinstance(self.language, Language):
            raise ValueError("language must be a Language")

        if isinstance(self.expected_findings, (str, bytes)) or not hasattr(
            self.expected_findings, "__iter__"
        ):
            raise ValueError("expected_findings must be a sequence")

        expected = tuple(self.expected_findings)

        for item in expected:
            if not isinstance(item, ExpectedFinding):
                raise ValueError("expected_findings must hold ExpectedFinding values")

        ids = [item.expected_id for item in expected]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})

        if duplicates:
            raise ValueError(
                f"case {self.case_id!r} has duplicate expected_id: "
                + ", ".join(repr(i) for i in duplicates)
            )

        object.__setattr__(
            self,
            "expected_findings",
            tuple(sorted(expected, key=lambda item: item.expected_id)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "language": self.language.value,
            "expected_findings": [item.to_dict() for item in self.expected_findings],
        }

    @classmethod
    def from_dict(cls, data: Any, path: str = "case"):
        fields = _object(
            data, path, {"case_id", "language", "expected_findings"}, set()
        )
        language = fields["language"]

        if not isinstance(language, str):
            raise ValueError(f"{path}.language must be a string")

        try:
            language = Language(language)
        except ValueError:
            raise ValueError(f"{path}.language is not a known language") from None

        items = fields["expected_findings"]

        if not isinstance(items, list):
            raise ValueError(f"{path}.expected_findings must be a list")

        return cls(
            case_id=fields["case_id"],
            language=language,
            expected_findings=tuple(
                ExpectedFinding.from_dict(item, f"{path}.expected_findings[{index}]")
                for index, item in enumerate(items)
            ),
        )


@dataclass(frozen=True)
class Benchmark:
    """A set of benchmark cases with unique ``case_id`` values.

    ``cases`` is stored as a tuple sorted by ``case_id``.
    """

    cases: tuple[BenchmarkCase, ...] = ()

    def __post_init__(self):
        if isinstance(self.cases, (str, bytes)) or not hasattr(self.cases, "__iter__"):
            raise ValueError("cases must be a sequence")

        cases = tuple(self.cases)

        for case in cases:
            if not isinstance(case, BenchmarkCase):
                raise ValueError("cases must hold BenchmarkCase values")

        ids = [case.case_id for case in cases]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})

        if duplicates:
            raise ValueError(
                "duplicate case_id: " + ", ".join(repr(i) for i in duplicates)
            )

        object.__setattr__(
            self, "cases", tuple(sorted(cases, key=lambda case: case.case_id))
        )

    def case(self, case_id: str) -> BenchmarkCase:
        """Return the case with this ID. Raises ``KeyError`` if there is none."""

        for case in self.cases:
            if case.case_id == case_id:
                return case

        raise KeyError(case_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": BENCHMARK_SCHEMA_VERSION,
            "cases": [case.to_dict() for case in self.cases],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "Benchmark":
        fields = _object(data, "benchmark", {"schema_version", "cases"}, set())

        if fields["schema_version"] != BENCHMARK_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported benchmark schema_version {fields['schema_version']!r}"
                f" (expected {BENCHMARK_SCHEMA_VERSION!r})"
            )

        items = fields["cases"]

        if not isinstance(items, list):
            raise ValueError("benchmark.cases must be a list")

        return cls(
            tuple(
                BenchmarkCase.from_dict(item, f"benchmark.cases[{index}]")
                for index, item in enumerate(items)
            )
        )

    def to_json(self) -> str:
        """Deterministic JSON: sorted keys, 2-space indent, ASCII only.

        There is no trailing newline.
        """

        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )

    @classmethod
    def from_json(cls, text: str) -> "Benchmark":
        """Parse benchmark JSON strictly. Raises ``ValueError`` on bad input."""

        if not isinstance(text, str):
            raise ValueError("benchmark JSON must be a string")

        try:
            data = json.loads(
                text,
                parse_constant=_reject_constant,
                object_pairs_hook=_no_duplicate_keys,
            )
        except RecursionError:
            raise ValueError("invalid benchmark JSON: nested too deeply") from None

        return cls.from_dict(data)


# -- strict JSON helpers (standard library only) -----------------------


def _reject_constant(name: str):
    raise ValueError(f"invalid benchmark JSON constant: {name}")


def _no_duplicate_keys(pairs):
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"invalid benchmark JSON: duplicate key {key!r}")

        result[key] = value

    return result


def _object(data: Any, path: str, required: set[str], optional: set[str]):
    """Check that ``data`` is an object with exactly the allowed keys."""

    if not isinstance(data, dict):
        raise ValueError(f"{path} must be an object")

    if not all(isinstance(key, str) for key in data):
        raise ValueError(f"{path} keys must be strings")

    missing = sorted(required - data.keys())

    if missing:
        raise ValueError(f"{path} is missing: " + ", ".join(missing))

    unknown = sorted(data.keys() - required - optional)

    if unknown:
        raise ValueError(f"{path} has unknown keys: " + ", ".join(unknown))

    return data
