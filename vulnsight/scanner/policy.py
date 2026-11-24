from dataclasses import dataclass
from enum import Enum

from vulnsight.scanner.specs import SanitizerSpec, SourceSpec
from vulnsight.scanner.taint_model import SourceKind


class ParameterMode(str, Enum):
    """How function parameters are treated as taint sources.

    ``STRICT`` (the default): parameters are clean. Only declared sources
    (``input()``, ``sys.argv`` and so on) start taint.

    ``RECALL`` (experimental): the parameters of module-level functions and
    class methods are tainted with ``SourceKind.PARAMETER``. This finds more
    candidates, with many more false positives, so findings that rest only on
    parameter taint get low confidence. It exists to feed the ML verifier.
    """

    STRICT = "strict"
    RECALL = "recall"


@dataclass(frozen=True, slots=True)
class TaintPolicy:
    sources: tuple[SourceSpec, ...]
    sanitizers: tuple[SanitizerSpec, ...]
    parameter_mode: ParameterMode = ParameterMode.STRICT

    def __post_init__(self):
        if not isinstance(self.parameter_mode, ParameterMode):
            raise ValueError("parameter_mode must be a ParameterMode")


def create_default_policy(parameter_mode=ParameterMode.STRICT):
    sources = (
        SourceSpec(
            names=frozenset({"input", "builtins.input"}),
            kind=SourceKind.INTERACTIVE,
            origin_id="input()",
        ),
        SourceSpec(
            names=frozenset(
                {
                    "sys.stdin.read",
                    "sys.stdin.readline",
                }
            ),
            kind=SourceKind.STDIN,
            origin_id="sys.stdin",
        ),
        SourceSpec(
            roots=frozenset({"sys.argv"}),
            kind=SourceKind.CLI_ARG,
            origin_id="sys.argv",
            container=True,
        ),
        SourceSpec(
            names=frozenset({"os.getenv"}),
            kind=SourceKind.ENVIRONMENT,
            origin_id="os.getenv",
        ),
        SourceSpec(
            roots=frozenset({"os.environ"}),
            kind=SourceKind.ENVIRONMENT,
            origin_id="os.environ",
            container=True,
        ),
    )

    sanitizers = (
        SanitizerSpec(
            names=frozenset({"int", "float", "bool", "len"}),
            neutralizes=frozenset({"*"}),
            platforms=frozenset({"posix", "windows"}),
            note="Restricts the input to a specific type or value form.",
        ),
        SanitizerSpec(
            names=frozenset({"shlex.quote"}),
            neutralizes=frozenset({"CWE-78"}),
            platforms=frozenset({"posix"}),
            note="POSIX shell quoting does not protect Windows cmd.exe.",
        ),
    )

    return TaintPolicy(
        sources=sources,
        sanitizers=sanitizers,
        parameter_mode=parameter_mode,
    )
