from dataclasses import dataclass

from vulnsight.scanner.specs import SanitizerSpec, SourceSpec
from vulnsight.scanner.taint_model import SourceKind


@dataclass(frozen=True, slots=True)
class TaintPolicy:
    sources: tuple[SourceSpec, ...]
    sanitizers: tuple[SanitizerSpec, ...]
    pass_through: frozenset[str]


def create_default_policy():
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
        ),
        SourceSpec(
            names=frozenset({"os.getenv"}),
            kind=SourceKind.ENVIRONMENT,
            origin_id="os.getenv",
            max_confidence="low",
        ),
        SourceSpec(
            roots=frozenset({"os.environ"}),
            kind=SourceKind.ENVIRONMENT,
            origin_id="os.environ",
            max_confidence="low",
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

    pass_through = frozenset(
        {
            "str",
            "repr",
            "format",
            "join",
            "os.path.join",
        }
    )

    return TaintPolicy(
        sources=sources,
        sanitizers=sanitizers,
        pass_through=pass_through,
    )
