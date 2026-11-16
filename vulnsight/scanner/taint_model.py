from dataclasses import dataclass
from enum import Enum

MAX_TRACE_STEPS = 12


class SourceKind(str, Enum):
    INTERACTIVE = "interactive"
    STDIN = "stdin"
    CLI_ARG = "cli_arg"
    ENVIRONMENT = "environment"
    FRAMEWORK = "framework"
    FILE = "file"
    NETWORK = "network"


class TraceKind(str, Enum):
    SOURCE = "source"
    ASSIGN = "assign"
    CONCAT = "concat"
    FORMAT = "format"
    CALL = "call"
    ALIAS = "alias"
    CONTAINER = "container"
    LOOP = "loop"
    PARTIAL_SANITIZER = "partial_sanitizer"
    ELIDED = "elided"


class TaintEffect(str, Enum):
    CLEAN = "clean"
    RAW = "raw"
    PARTIAL = "partial"
    NEUTRALIZED = "neutralized"


@dataclass(frozen=True, slots=True)
class TaintOrigin:
    origin_id: str
    kind: SourceKind
    line: int
    col: int

    def __post_init__(self):
        if not self.origin_id:
            raise ValueError("origin_id cannot be empty")
        if self.line < 0 or self.col < 0:
            raise ValueError("Source positions cannot be negative")


@dataclass(frozen=True, slots=True)
class TraceStep:
    kind: TraceKind
    line: int
    col: int
    text: str = ""

    def __post_init__(self):
        if self.line < 0 or self.col < 0:
            raise ValueError("Trace positions cannot be negative")

        object.__setattr__(self, "text", self.text[:80])


@dataclass(frozen=True, slots=True)
class Neutralization:
    cwe: str
    platforms: frozenset[str]
    via: str

    def __post_init__(self):
        allowed = {"posix", "windows"}

        if self.cwe != "*" and not self.cwe.startswith("CWE-"):
            raise ValueError(f"Invalid CWE identifier: {self.cwe}")

        if not self.platforms:
            raise ValueError("At least one platform is required")

        if not self.platforms.issubset(allowed):
            raise ValueError("Platforms must be posix and/or windows")

        if not self.via:
            raise ValueError("Sanitizer name cannot be empty")


@dataclass(frozen=True, slots=True)
class TaintLabel:
    origin: TaintOrigin
    trace: tuple[TraceStep, ...]
    neutralizations: frozenset[Neutralization] = frozenset()

    def __post_init__(self):
        if not self.trace:
            raise ValueError("A taint label must have a source trace")

        if self.trace[0].kind != TraceKind.SOURCE:
            raise ValueError("The first trace step must be SOURCE")

        object.__setattr__(
            self,
            "trace",
            _limit_trace(self.trace),
        )


def _limit_trace(trace):
    """Keep the first and latest steps within the trace budget."""

    trace = tuple(trace)

    if len(trace) <= MAX_TRACE_STEPS:
        return trace

    first_count = MAX_TRACE_STEPS // 2
    last_count = MAX_TRACE_STEPS - first_count - 1

    marker = TraceStep(
        kind=TraceKind.ELIDED,
        line=trace[first_count].line,
        col=trace[first_count].col,
        text="Intermediate trace steps omitted",
    )

    return trace[:first_count] + (marker,) + trace[-last_count:]


@dataclass(frozen=True, slots=True)
class TaintValue:
    labels: tuple[TaintLabel, ...] = ()

    def __post_init__(self):
        # One label per origin identity.
        grouped = {}

        for label in self.labels:
            key = (
                label.origin.origin_id,
                label.origin.line,
                label.origin.col,
            )

            previous = grouped.get(key)

            if previous is None:
                grouped[key] = label
                continue

            # Keep the shorter trace and only neutralizations
            # common to both paths.
            shortest = min(
                (previous, label),
                key=lambda item: (len(item.trace), item.trace),
            )

            grouped[key] = TaintLabel(
                origin=shortest.origin,
                trace=shortest.trace,
                neutralizations=(previous.neutralizations & label.neutralizations),
            )

        ordered = tuple(grouped[key] for key in sorted(grouped))

        object.__setattr__(self, "labels", ordered)

    @classmethod
    def clean(cls):
        return cls()

    @classmethod
    def from_origin(cls, origin):
        source_step = TraceStep(
            kind=TraceKind.SOURCE,
            line=origin.line,
            col=origin.col,
            text=origin.origin_id,
        )

        return cls(
            labels=(
                TaintLabel(
                    origin=origin,
                    trace=(source_step,),
                ),
            )
        )

    def join(self, other):
        """Conservatively combine taint from two possible paths."""

        return TaintValue(self.labels + other.labels)

    def with_step(self, step):
        """Append a step to every origin trace."""

        return TaintValue(
            tuple(
                TaintLabel(
                    origin=label.origin,
                    trace=label.trace + (step,),
                    neutralizations=label.neutralizations,
                )
                for label in self.labels
            )
        )

    def neutralized(self, neutralization):
        """Record a sanitizer application without deleting provenance."""

        return TaintValue(
            tuple(
                TaintLabel(
                    origin=label.origin,
                    trace=label.trace,
                    neutralizations=(label.neutralizations | {neutralization}),
                )
                for label in self.labels
            )
        )

    def effective_for(self, cwe, target_platforms):
        """Determine whether taint remains dangerous for a target."""

        if not self.labels:
            return TaintEffect.CLEAN

        target_platforms = frozenset(target_platforms)

        has_raw = False
        has_partial = False

        for label in self.labels:
            covered_platforms = set()

            for item in label.neutralizations:
                if item.cwe in {cwe, "*"}:
                    covered_platforms.update(item.platforms)

            if target_platforms.issubset(covered_platforms):
                continue

            if target_platforms.intersection(covered_platforms):
                has_partial = True
            else:
                has_raw = True

        if has_raw:
            return TaintEffect.RAW

        if has_partial:
            return TaintEffect.PARTIAL

        return TaintEffect.NEUTRALIZED

    def signature(self):
        """Return a stable signature that ignores trace details."""

        return tuple(
            (
                label.origin.origin_id,
                label.origin.line,
                label.origin.col,
                tuple(
                    sorted(
                        (
                            item.cwe,
                            tuple(sorted(item.platforms)),
                            item.via,
                        )
                        for item in label.neutralizations
                    )
                ),
            )
            for label in self.labels
        )

    def __bool__(self):
        return bool(self.labels)
