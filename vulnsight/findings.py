"""Finding v2: structured vulnerability findings with evidence and identity.

The legacy ``vulnsight.models.Finding`` is unchanged and still produced by the
current detector. Finding v2 lives here until the detector migrates.

Identity, in short (see ``docs/finding-schema.md``):

* ``fingerprint``: cross-scan grouping key. Ignores line, column and file.
* ``finding_id``: ``fingerprint`` plus ``occurrence``. Unique inside one
  ``ScanResult``. It is scan-local and not a permanent identifier.
* ``evidence_signature``: location-free summary of the taint evidence.
* ``structure_hash``: supplied by the producer and only stored here.
"""

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from vulnsight.codec import (
    Reader,
    SchemaError,
    label_from_reader,
    label_to_dict,
)
from vulnsight.scanner.scope import ResolutionCertainty
from vulnsight.scanner.taint_model import TaintEffect, TaintLabel

FINGERPRINT_PREFIX = "vulnsight.fingerprint.v1"
EVIDENCE_SIGNATURE_PREFIX = "vulnsight.evidence-signature.v1"

# Field and record separators used when hashing. Text containing them is
# rejected, so field boundaries are always unambiguous.
_FIELD_SEPARATOR = "\x1f"
_RECORD_SEPARATOR = "\x1e"

# Placeholders that are never valid names. See ``_sink_part``.
RESERVED_NO_SINK = "<no-sink>"
RESERVED_UNKNOWN_FUNCTION = "<unknown>"

_CWE_PATTERN = re.compile(r"CWE-[0-9]+")
_HASH_PATTERN = re.compile(r"[0-9a-f]{32}")


class Language(str, Enum):
    PYTHON = "python"
    C = "c"
    CPP = "cpp"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SeverityLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationVerdict(str, Enum):
    KEPT = "kept"
    SUPPRESSED = "suppressed"


# ---------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------


def require_text(name: str, value: Any) -> str:
    """Validate a non-empty string that can be hashed and encoded."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")

    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be valid Unicode text") from None

    return value


def _hashable_text(name: str, value: Any) -> str:
    """Validate text that is also used as a hash input."""

    require_text(name, value)

    if _FIELD_SEPARATOR in value or _RECORD_SEPARATOR in value:
        raise ValueError(f"{name} contains a reserved separator character")

    return value


def require_integer(name: str, value: Any, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")

    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")

    return value


def require_optional_integer(name: str, value: Any, minimum: int) -> int | None:
    if value is None:
        return None

    return require_integer(name, value, minimum)


def _enum(name: str, value: Any, enum_type: type[Enum]):
    if not isinstance(value, enum_type):
        raise ValueError(f"{name} must be a {enum_type.__name__}")

    return value


def _score(name: str, value: Any, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{name} must be a number")

    try:
        value = float(value)
    except OverflowError:
        # An integer too large for a float is far outside any valid range.
        raise ValueError(f"{name} must be between 0 and {maximum:g}") from None

    if not 0.0 <= value <= maximum:
        raise ValueError(f"{name} must be between 0 and {maximum:g}")

    return value


def normalize_path(path: str) -> str:
    """Store paths with forward slashes so output is platform independent."""

    return require_text("path", path).replace("\\", "/")


# ---------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------


def short_hash(prefix: str, *parts: str) -> str:
    """Return a 32-character hex digest of a prefix and its parts.

    Parts are joined with a separator character that parts may not contain,
    so ``("ab", "c")`` and ``("a", "bc")`` never share a digest. Producers can
    use this to build a ``structure_hash`` value.
    """

    for part in (prefix, *parts):
        require_text("hash part", part)

        if _FIELD_SEPARATOR in part:
            raise ValueError("hash part contains the reserved field separator")

    data = _FIELD_SEPARATOR.join((prefix, *parts)).encode("utf-8")

    return hashlib.sha256(data).hexdigest()[:32]


def _sink_part(sink: "Sink | None") -> str:
    """Encode a sink, or its absence, for hashing.

    Both forms carry a tag that the other cannot produce: a real sink is
    ``sink:<callee>`` and an absent sink is ``no-sink``. ``no-sink`` has no
    colon, so no callee can ever encode to it.
    """

    if sink is None:
        return "no-sink"

    return f"sink:{sink.callee}"


def _function_part(name: str | None) -> str:
    if name is None:
        return "function-unknown"

    return f"function:{name}"


# ---------------------------------------------------------------
# Value types
# ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Location:
    """Where a finding is. ``file`` is ``None`` for in-memory source."""

    file: str | None
    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None

    def __post_init__(self):
        if self.file is not None:
            object.__setattr__(self, "file", normalize_path(self.file))

        require_integer("line", self.line, 1)
        require_integer("column", self.column, 0)
        require_optional_integer("end_line", self.end_line, 1)
        require_optional_integer("end_column", self.end_column, 0)

        if self.end_line is None and self.end_column is not None:
            raise ValueError("end_column requires end_line")

        if self.end_line is not None and self.end_line < self.line:
            raise ValueError("end_line cannot be before line")

        if (
            self.end_line == self.line
            and self.end_column is not None
            and self.end_column < self.column
        ):
            raise ValueError("end_column cannot be before column")

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    @classmethod
    def from_reader(cls, reader: Reader) -> "Location":
        try:
            location = cls(
                file=reader.optional_text("file"),
                line=reader.integer("line"),
                column=reader.integer("column"),
                end_line=reader.optional_integer("end_line"),
                end_column=reader.optional_integer("end_column"),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"{reader.path}: {error}") from error

        reader.finish()

        return location


@dataclass(frozen=True, slots=True)
class Sink:
    """The operation where data becomes dangerous."""

    callee: str
    certainty: ResolutionCertainty

    def __post_init__(self):
        _hashable_text("callee", self.callee)

        if self.callee in (RESERVED_NO_SINK, RESERVED_UNKNOWN_FUNCTION):
            raise ValueError(f"callee {self.callee!r} is reserved")

        _enum("certainty", self.certainty, ResolutionCertainty)

        if self.certainty == ResolutionCertainty.NONE:
            raise ValueError("a reported sink must have a resolved callee")

    def to_dict(self) -> dict[str, Any]:
        return {"callee": self.callee, "certainty": self.certainty.value}

    @classmethod
    def from_reader(cls, reader: Reader) -> "Sink":
        try:
            sink = cls(
                callee=reader.text("callee"),
                certainty=reader.enum("certainty", ResolutionCertainty),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"{reader.path}: {error}") from error

        reader.finish()

        return sink


@dataclass(frozen=True, slots=True)
class SeverityAssessment:
    """Severity metadata. Absent on a finding means "not assessed"."""

    level: SeverityLevel
    method: str
    score: float | None = None
    vector: str | None = None
    assumptions: tuple[str, ...] = ()

    def __post_init__(self):
        _enum("level", self.level, SeverityLevel)
        require_text("method", self.method)

        if self.score is not None:
            object.__setattr__(self, "score", _score("score", self.score, 10.0))

        if self.vector is not None:
            require_text("vector", self.vector)

        # A bare string would be split into characters and bytes into integers.
        if not isinstance(self.assumptions, tuple | list):
            raise ValueError("assumptions must be a tuple or list of strings")

        assumptions = tuple(self.assumptions)

        for item in assumptions:
            require_text("assumption", item)

        object.__setattr__(self, "assumptions", assumptions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "method": self.method,
            "score": self.score,
            "vector": self.vector,
            "assumptions": list(self.assumptions),
        }

    @classmethod
    def from_reader(cls, reader: Reader) -> "SeverityAssessment":
        try:
            assessment = cls(
                level=reader.enum("level", SeverityLevel),
                method=reader.text("method"),
                score=reader.optional_number("score"),
                vector=reader.optional_text("vector"),
                assumptions=reader.strings("assumptions"),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"{reader.path}: {error}") from error

        reader.finish()

        return assessment


@dataclass(frozen=True, slots=True)
class Verification:
    """Result of an ML verification step. Absent means "not run"."""

    verdict: VerificationVerdict
    score: float
    model_id: str

    def __post_init__(self):
        _enum("verdict", self.verdict, VerificationVerdict)
        object.__setattr__(self, "score", _score("score", self.score, 1.0))
        require_text("model_id", self.model_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "model_id": self.model_id,
        }

    @classmethod
    def from_reader(cls, reader: Reader) -> "Verification":
        try:
            verification = cls(
                verdict=reader.enum("verdict", VerificationVerdict),
                score=reader.number("score"),
                model_id=reader.text("model_id"),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"{reader.path}: {error}") from error

        reader.finish()

        return verification


# ---------------------------------------------------------------
# Finding
# ---------------------------------------------------------------

# Keys of the legacy v1 ``Finding`` that v2 still answers to.
_LEGACY_KEYS = frozenset(
    {
        "function",
        "line",
        "cwe",
        "severity",
        "message",
        "rule_id",
        "confidence",
        "source",
        "sink",
    }
)


def _label_order(label: TaintLabel):
    origin = label.origin

    return (origin.origin_id, origin.line, origin.col)


@dataclass(frozen=True, slots=True)
class Finding:
    """A potential vulnerability together with its evidence.

    Optional values never double as "no": ``None`` always means the
    information is unknown, absent or was not produced, while a real value
    (``SeverityLevel.NONE``, ``VerificationVerdict.KEPT``, an empty tuple) is
    a genuine answer.
    """

    rule_id: str
    cwe: str
    language: Language
    message: str
    location: Location
    confidence: ConfidenceLevel
    enclosing_function: str | None = None
    sink: Sink | None = None
    evidence: tuple[TaintLabel, ...] = ()
    taint_effect: TaintEffect | None = None
    severity: SeverityAssessment | None = None
    verification: Verification | None = None
    structure_hash: str | None = None
    occurrence: int = 0

    def __post_init__(self):
        _hashable_text("rule_id", self.rule_id)
        require_text("message", self.message)

        if not isinstance(self.cwe, str) or not _CWE_PATTERN.fullmatch(self.cwe):
            raise ValueError("cwe must look like 'CWE-78'")

        _enum("language", self.language, Language)
        _enum("confidence", self.confidence, ConfidenceLevel)

        if not isinstance(self.location, Location):
            raise ValueError("location must be a Location")

        if self.enclosing_function is not None:
            _hashable_text("enclosing_function", self.enclosing_function)

            if self.enclosing_function == RESERVED_UNKNOWN_FUNCTION:
                raise ValueError(
                    f"enclosing_function {RESERVED_UNKNOWN_FUNCTION!r} is reserved"
                )

        if self.sink is not None and not isinstance(self.sink, Sink):
            raise ValueError("sink must be a Sink or None")

        evidence = tuple(self.evidence)

        for label in evidence:
            if not isinstance(label, TaintLabel):
                raise ValueError("evidence must contain TaintLabel objects")

            _hashable_text("origin_id", label.origin.origin_id)

        object.__setattr__(self, "evidence", tuple(sorted(evidence, key=_label_order)))

        if evidence and self.sink is None:
            raise ValueError("taint evidence requires a sink")

        if self.taint_effect is not None:
            _enum("taint_effect", self.taint_effect, TaintEffect)

            if self.taint_effect not in (TaintEffect.RAW, TaintEffect.PARTIAL):
                raise ValueError("taint_effect must be RAW, PARTIAL or None")

            if not evidence:
                raise ValueError("taint_effect requires taint evidence")

        if self.severity is not None and not isinstance(
            self.severity, SeverityAssessment
        ):
            raise ValueError("severity must be a SeverityAssessment or None")

        if self.verification is not None and not isinstance(
            self.verification, Verification
        ):
            raise ValueError("verification must be a Verification or None")

        if self.structure_hash is not None and not (
            isinstance(self.structure_hash, str)
            and _HASH_PATTERN.fullmatch(self.structure_hash)
        ):
            raise ValueError("structure_hash must be 32 lowercase hex characters")

        require_integer("occurrence", self.occurrence, 0)

    # -- identity --------------------------------------------------

    @property
    def fingerprint(self) -> str:
        """Cross-scan grouping key: rule, CWE, sink and enclosing function.

        Line, column and file are not part of it. Findings without a sink or
        without a known function still get a deterministic value.
        """

        return short_hash(
            FINGERPRINT_PREFIX,
            self.rule_id,
            self.cwe,
            _sink_part(self.sink),
            _function_part(self.enclosing_function),
        )

    @property
    def evidence_signature(self) -> str | None:
        """Location-free summary of the taint evidence, or ``None``.

        Each origin contributes its id and its ordered trace-kind sequence.
        Origins are sorted by id, then kinds, so the value does not depend on
        file position. ``None`` when there is no taint evidence.
        """

        if not self.evidence:
            return None

        entries = sorted(
            (
                label.origin.origin_id,
                tuple(step.kind.value for step in label.trace),
            )
            for label in self.evidence
        )

        return short_hash(
            EVIDENCE_SIGNATURE_PREFIX,
            self.rule_id,
            _sink_part(self.sink),
            *(
                f"{origin_id}{_RECORD_SEPARATOR}{','.join(kinds)}"
                for origin_id, kinds in entries
            ),
        )

    @property
    def finding_id(self) -> str:
        """Scan-local unique id. Not a permanent cross-scan identifier."""

        return f"{self.fingerprint}-{self.occurrence}"

    # -- legacy dictionary-style access ----------------------------

    def _legacy_value(self, key: str) -> Any:
        if key == "function" or key == "sink":
            return "" if self.sink is None else self.sink.callee

        if key == "line":
            return self.location.line

        if key == "severity":
            if self.severity is None:
                return "Review required"

            return self.severity.level.value

        if key == "confidence":
            return self.confidence.value

        if key == "source":
            return ", ".join(sorted({item.origin.origin_id for item in self.evidence}))

        return getattr(self, key)

    def __getitem__(self, key: str) -> Any:
        """Read-only access using the legacy v1 key names."""

        if key not in _LEGACY_KEYS:
            raise KeyError(key)

        return self._legacy_value(key)

    def get(self, key: str, default: Any = None) -> Any:
        """Legacy ``get``: unknown keys return the default."""

        if key not in _LEGACY_KEYS:
            return default

        return self._legacy_value(key)

    # -- serialization ---------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible form, including derived identifiers."""

        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "language": self.language.value,
            "message": self.message,
            "location": self.location.to_dict(),
            "confidence": self.confidence.value,
            "enclosing_function": self.enclosing_function,
            "sink": None if self.sink is None else self.sink.to_dict(),
            "evidence": [label_to_dict(label) for label in self.evidence],
            "taint_effect": (
                None if self.taint_effect is None else self.taint_effect.value
            ),
            "severity": None if self.severity is None else self.severity.to_dict(),
            "verification": (
                None if self.verification is None else self.verification.to_dict()
            ),
            "structure_hash": self.structure_hash,
            "occurrence": self.occurrence,
            "fingerprint": self.fingerprint,
            "evidence_signature": self.evidence_signature,
            "finding_id": self.finding_id,
        }

    @classmethod
    def from_dict(cls, data: Any, path: str = "finding") -> "Finding":
        """Build a finding from JSON data, rejecting anything malformed."""

        return cls.from_reader(Reader(data, path))

    @classmethod
    def from_reader(cls, reader: Reader) -> "Finding":
        sink_reader = reader.optional_object("sink")
        severity_reader = reader.optional_object("severity")
        verification_reader = reader.optional_object("verification")

        try:
            finding = cls(
                rule_id=reader.text("rule_id"),
                cwe=reader.text("cwe"),
                language=reader.enum("language", Language),
                message=reader.text("message"),
                location=Location.from_reader(reader.object("location")),
                confidence=reader.enum("confidence", ConfidenceLevel),
                enclosing_function=reader.optional_text("enclosing_function"),
                sink=None if sink_reader is None else Sink.from_reader(sink_reader),
                evidence=tuple(
                    label_from_reader(item) for item in reader.objects("evidence")
                ),
                taint_effect=reader.optional_enum("taint_effect", TaintEffect),
                severity=(
                    None
                    if severity_reader is None
                    else SeverityAssessment.from_reader(severity_reader)
                ),
                verification=(
                    None
                    if verification_reader is None
                    else Verification.from_reader(verification_reader)
                ),
                structure_hash=reader.optional_text("structure_hash"),
                occurrence=reader.integer("occurrence"),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"{reader.path}: {error}") from error

        derived = {
            "fingerprint": finding.fingerprint,
            "evidence_signature": finding.evidence_signature,
            "finding_id": finding.finding_id,
        }

        for key, expected in derived.items():
            actual = reader.optional_text(key)

            if actual != expected:
                raise SchemaError(
                    f"{reader.path}.{key}: does not match the finding's content"
                )

        reader.finish()

        return finding


# ---------------------------------------------------------------
# Ordering and occurrence numbers
# ---------------------------------------------------------------


def _position_key(finding: Finding):
    location = finding.location

    return (
        location.file or "",
        location.line,
        location.column,
        -1 if location.end_line is None else location.end_line,
        -1 if location.end_column is None else location.end_column,
        finding.evidence_signature or "",
    )


def finding_sort_key(finding: Finding):
    """Canonical order of findings inside a scan result."""

    location = finding.location

    return (
        location.file or "",
        location.line,
        location.column,
        finding.rule_id,
        finding.finding_id,
    )


def assign_occurrences(findings) -> tuple[Finding, ...]:
    """Number findings that share a fingerprint, deterministically.

    Within each fingerprint group findings are ordered by file path, line,
    column, end position and evidence signature, then numbered from zero. The
    result depends only on the findings themselves, never on the order they
    were passed in or on filesystem traversal order. Paths are compared as
    plain strings, so callers should pass paths relative to the scan target.

    Two findings that are identical on every ordering key cannot be told
    apart and raise ``ValueError``.
    """

    groups: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        if not isinstance(finding, Finding):
            raise ValueError("assign_occurrences expects Finding objects")

        groups[finding.fingerprint].append(finding)

    numbered = []

    for group in groups.values():
        ordered = sorted(group, key=_position_key)

        for earlier, later in zip(ordered, ordered[1:], strict=False):
            if _position_key(earlier) == _position_key(later):
                raise ValueError(
                    "duplicate finding at "
                    f"{earlier.location.file or '<memory>'}:"
                    f"{earlier.location.line}:{earlier.location.column}"
                )

        numbered.extend(
            replace(finding, occurrence=index) for index, finding in enumerate(ordered)
        )

    return tuple(sorted(numbered, key=finding_sort_key))
