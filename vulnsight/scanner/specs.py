from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from vulnsight.scanner.taint_model import SourceKind


class GuardResult(str, Enum):
    APPLIES = "applies"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class GuardDecision:
    result: GuardResult
    note: str = ""


@dataclass(frozen=True, slots=True)
class SourceSpec:
    names: frozenset[str] = frozenset()
    roots: frozenset[str] = frozenset()
    kind: SourceKind = SourceKind.INTERACTIVE
    origin_id: str = ""
    # True only when the source value is a mapping or sequence (os.environ,
    # sys.argv, a request object). The engine does not infer this: a source
    # not declared as a container never propagates through get() or copy().
    container: bool = False

    def __post_init__(self):
        if self.container and not self.origin_id:
            raise ValueError("A container source needs an origin_id")


@dataclass(frozen=True, slots=True)
class SanitizerSpec:
    names: frozenset[str]
    neutralizes: frozenset[str]
    platforms: frozenset[str] = frozenset({"posix", "windows"})
    note: str = ""


@dataclass(frozen=True, slots=True)
class ArgSelector:
    positions: tuple[int, ...] = (0,)
    keywords: tuple[str, ...] = ("args", "command", "cmd")


Guard = Callable[[object], GuardDecision]


@dataclass(frozen=True, slots=True)
class SinkSpec:
    rule_id: str
    cwe: str
    names: frozenset[str] = frozenset()
    selector: ArgSelector = field(default_factory=ArgSelector)
    guard: Guard | None = None

    def __post_init__(self):
        if not self.rule_id:
            raise ValueError("rule_id cannot be empty")

        if not self.cwe.startswith("CWE-"):
            raise ValueError(f"Invalid CWE identifier: {self.cwe}")
