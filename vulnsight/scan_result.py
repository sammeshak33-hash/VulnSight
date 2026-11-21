"""ScanResult: the result of scanning one target, independent of any CLI.

A ``ScanResult`` holds findings, issues (errors and warnings), status and
metadata, and converts to and from deterministic, strictly validated JSON.
Nothing here reads, executes or imports scanned source code.
"""

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from vulnsight.codec import (
    Reader,
    SchemaError,
    dumps_canonical,
    loads_strict,
)
from vulnsight.findings import (
    Finding,
    finding_sort_key,
    normalize_path,
    require_optional_integer,
    require_text,
)

SCHEMA_VERSION = "2.0"

# Versions this code can read. A change here is a deliberate, documented
# decision: see "Schema versioning" in docs/finding-schema.md.
SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})

_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")


class ScanStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class IssueLevel(str, Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class ScanIssue:
    """An error or warning raised while scanning."""

    level: IssueLevel
    code: str
    message: str
    file: str | None = None
    line: int | None = None

    def __post_init__(self):
        if not isinstance(self.level, IssueLevel):
            raise ValueError("level must be an IssueLevel")

        require_text("code", self.code)
        require_text("message", self.message)

        if self.file is not None:
            object.__setattr__(self, "file", normalize_path(self.file))

        require_optional_integer("line", self.line, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "code": self.code,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }

    @classmethod
    def from_reader(cls, reader: Reader) -> "ScanIssue":
        try:
            issue = cls(
                level=reader.enum("level", IssueLevel),
                code=reader.text("code"),
                message=reader.text("message"),
                file=reader.optional_text("file"),
                line=reader.optional_integer("line"),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"{reader.path}: {error}") from error

        reader.finish()

        return issue


def _issue_order(issue: ScanIssue):
    return (
        issue.level.value,
        issue.file or "",
        issue.line or 0,
        issue.code,
        issue.message,
    )


@dataclass(frozen=True, slots=True)
class ScanMetadata:
    """Facts about the scan itself.

    ``files_scanned`` is ``None`` when unknown and ``0`` when nothing was
    scanned. ``created_at`` is ``None`` unless the caller sets it, which keeps
    output reproducible. ``settings`` holds free-form string settings, stored
    as sorted ``(key, value)`` pairs.
    """

    files_scanned: int | None = None
    tool_version: str | None = None
    created_at: str | None = None
    settings: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        require_optional_integer("files_scanned", self.files_scanned, 0)

        if self.tool_version is not None:
            require_text("tool_version", self.tool_version)

        if self.created_at is not None:
            self._check_timestamp(self.created_at)

        pairs = []

        for pair in self.settings:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("settings must be (key, value) pairs")

            key, value = pair
            pairs.append(
                (require_text("setting key", key), require_text("setting value", value))
            )

        keys = [key for key, _ in pairs]

        if len(set(keys)) != len(keys):
            raise ValueError("settings keys must be unique")

        object.__setattr__(self, "settings", tuple(sorted(pairs)))

    @staticmethod
    def _check_timestamp(value: str):
        if not isinstance(value, str) or not _TIMESTAMP_PATTERN.fullmatch(value):
            raise ValueError("created_at must be a UTC timestamp ending in 'Z'")

        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("created_at is not a valid timestamp") from None

    @classmethod
    def with_settings(cls, settings: dict[str, str], **fields) -> "ScanMetadata":
        """Build metadata from a settings dictionary."""

        return cls(settings=tuple(settings.items()), **fields)

    def settings_dict(self) -> dict[str, str]:
        return dict(self.settings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "tool_version": self.tool_version,
            "created_at": self.created_at,
            "settings": dict(self.settings),
        }

    @classmethod
    def from_reader(cls, reader: Reader) -> "ScanMetadata":
        settings = reader.mapping("settings")

        for key, value in settings.items():
            if not isinstance(value, str):
                raise SchemaError(f"{reader.path}.settings.{key}: expected a string")

        try:
            metadata = cls(
                files_scanned=reader.optional_integer("files_scanned"),
                tool_version=reader.optional_text("tool_version"),
                created_at=reader.optional_text("created_at"),
                settings=tuple(settings.items()),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"{reader.path}: {error}") from error

        reader.finish()

        return metadata


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The outcome of scanning one target.

    Findings are kept in canonical order and must have unique ``finding_id``
    values. Status must agree with the issues: ``complete`` allows no errors,
    while ``partial`` and ``failed`` require at least one.
    """

    status: ScanStatus
    target: str | None = None
    findings: tuple[Finding, ...] = ()
    issues: tuple[ScanIssue, ...] = ()
    metadata: ScanMetadata = ScanMetadata()

    def __post_init__(self):
        if not isinstance(self.status, ScanStatus):
            raise ValueError("status must be a ScanStatus")

        if self.target is not None:
            object.__setattr__(self, "target", normalize_path(self.target))

        findings = tuple(self.findings)

        for finding in findings:
            if not isinstance(finding, Finding):
                raise ValueError("findings must contain Finding objects")

        ordered = tuple(sorted(findings, key=finding_sort_key))
        ids = [finding.finding_id for finding in ordered]

        if len(set(ids)) != len(ids):
            raise ValueError(
                "findings must have unique finding_id values; "
                "use assign_occurrences() to number them"
            )

        object.__setattr__(self, "findings", ordered)

        issues = tuple(self.issues)

        for issue in issues:
            if not isinstance(issue, ScanIssue):
                raise ValueError("issues must contain ScanIssue objects")

        object.__setattr__(self, "issues", tuple(sorted(issues, key=_issue_order)))

        if not isinstance(self.metadata, ScanMetadata):
            raise ValueError("metadata must be a ScanMetadata")

        has_errors = any(item.level == IssueLevel.ERROR for item in issues)

        if self.status == ScanStatus.COMPLETE and has_errors:
            raise ValueError("a complete scan cannot have error issues")

        if self.status != ScanStatus.COMPLETE and not has_errors:
            raise ValueError(f"a {self.status.value} scan needs an error issue")

    @property
    def schema_version(self) -> str:
        return SCHEMA_VERSION

    @property
    def errors(self) -> tuple[ScanIssue, ...]:
        return tuple(item for item in self.issues if item.level == IssueLevel.ERROR)

    @property
    def warnings(self) -> tuple[ScanIssue, ...]:
        return tuple(item for item in self.issues if item.level == IssueLevel.WARNING)

    def summary(self) -> dict[str, Any]:
        """Counts derived from the findings and issues. Never stored."""

        return {
            "findings": len(self.findings),
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "by_cwe": dict(sorted(Counter(f.cwe for f in self.findings).items())),
            "by_rule": dict(sorted(Counter(f.rule_id for f in self.findings).items())),
        }

    # -- serialization ---------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": self.metadata.to_dict(),
            "summary": self.summary(),
        }

    def to_json(self) -> str:
        """Deterministic JSON text (sorted keys, ASCII, LF, no timestamp)."""

        return dumps_canonical(self.to_dict())

    @classmethod
    def from_dict(cls, data: Any) -> "ScanResult":
        """Build a result from JSON data, rejecting anything malformed."""

        reader = Reader(data, "scan_result")
        version = reader.text("schema_version")

        if version not in SUPPORTED_SCHEMA_VERSIONS:
            supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
            raise SchemaError(
                f"scan_result.schema_version: {version!r} is not supported "
                f"(supported: {supported})"
            )

        try:
            result = cls(
                status=reader.enum("status", ScanStatus),
                target=reader.optional_text("target"),
                findings=tuple(
                    Finding.from_reader(item) for item in reader.objects("findings")
                ),
                issues=tuple(
                    ScanIssue.from_reader(item) for item in reader.objects("issues")
                ),
                metadata=ScanMetadata.from_reader(reader.object("metadata")),
            )
        except SchemaError:
            raise
        except ValueError as error:
            raise SchemaError(f"scan_result: {error}") from error

        if reader.mapping("summary") != result.summary():
            raise SchemaError(
                "scan_result.summary: does not match the findings and issues"
            )

        reader.finish()

        return result

    @classmethod
    def from_json(cls, text: str) -> "ScanResult":
        return cls.from_dict(loads_strict(text))


__all__ = [
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "IssueLevel",
    "ScanIssue",
    "ScanMetadata",
    "ScanResult",
    "ScanStatus",
]
