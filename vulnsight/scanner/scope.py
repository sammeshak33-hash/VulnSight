from dataclasses import dataclass, field
from enum import Enum

from vulnsight.scanner.taint_model import TaintValue


class BindingKind(str, Enum):
    IMPORT = "import"
    ALIAS = "alias"
    VARIABLE = "variable"
    PARAM = "param"
    FUNCTION = "function"
    CLASS = "class"
    STAR = "star"
    AMBIGUOUS = "ambiguous"


class ResolutionCertainty(str, Enum):
    DEFINITE = "definite"
    POSSIBLE = "possible"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class NameCandidate:
    kind: BindingKind | None
    dotted: str | None = None


@dataclass(frozen=True, slots=True)
class NameInfo:
    kind: BindingKind
    dotted: str | None = None
    taint: TaintValue = field(default_factory=TaintValue.clean)
    candidates: frozenset[NameCandidate] = frozenset()

    @classmethod
    def ambiguous(cls, candidates):
        return cls(
            kind=BindingKind.AMBIGUOUS,
            candidates=frozenset(candidates),
        )


@dataclass
class ScopeState:
    names: dict[str, NameInfo] = field(default_factory=dict)
    unreachable: bool = False

    def copy(self):
        return ScopeState(
            names=self.names.copy(),
            unreachable=self.unreachable,
        )

    def bind(self, name, info):
        if not name:
            raise ValueError("Variable name cannot be empty")

        self.names[name] = info

    def bind_name(
        self,
        name,
        kind=BindingKind.VARIABLE,
        dotted=None,
        taint=None,
    ):
        self.bind(
            name,
            NameInfo(
                kind=kind,
                dotted=dotted,
                taint=taint if taint is not None else TaintValue.clean(),
            ),
        )

    def bind_import(self, name, dotted):
        self.bind_name(name, kind=BindingKind.IMPORT, dotted=dotted)

    def bind_alias(self, name, dotted, taint=None):
        self.bind_name(
            name,
            kind=BindingKind.ALIAS,
            dotted=dotted,
            taint=taint,
        )

    def bind_parameter(self, name):
        self.bind_name(name, kind=BindingKind.PARAM)

    def bind_function(self, name):
        self.bind_name(name, kind=BindingKind.FUNCTION)

    def bind_class(self, name):
        self.bind_name(name, kind=BindingKind.CLASS)

    def get(self, name):
        return self.names.get(name)

    def get_taint(self, name):
        info = self.get(name)
        return info.taint if info is not None else TaintValue.clean()

    def resolve_dotted(self, name):
        root, separator, suffix = name.partition(".")

        info = self.get(root)

        if info is None:
            return name, ResolutionCertainty.DEFINITE

        if info.kind in {BindingKind.IMPORT, BindingKind.ALIAS}:
            resolved = info.dotted or root

            if separator:
                resolved = f"{resolved}.{suffix}"

            return resolved, ResolutionCertainty.DEFINITE

        if info.kind == BindingKind.AMBIGUOUS:
            candidates = {item.dotted for item in info.candidates if item.dotted}

            if len(candidates) == 1:
                resolved = next(iter(candidates))

                if separator:
                    resolved = f"{resolved}.{suffix}"

                return resolved, ResolutionCertainty.POSSIBLE

            return name, ResolutionCertainty.POSSIBLE

        return name, ResolutionCertainty.NONE

    @staticmethod
    def join(states):
        reachable = [state for state in states if not state.unreachable]

        if not reachable:
            return ScopeState(unreachable=True)

        all_names = set()

        for state in reachable:
            all_names.update(state.names)

        merged = ScopeState()

        for name in sorted(all_names):
            entries = [state.names.get(name) for state in reachable]

            present = [item for item in entries if item is not None]

            taint = TaintValue.clean()

            for item in present:
                taint = taint.join(item.taint)

            candidates = set()

            for item in entries:
                if item is None:
                    candidates.add(NameCandidate(None))
                elif item.kind == BindingKind.AMBIGUOUS:
                    candidates.update(item.candidates)
                else:
                    candidates.add(NameCandidate(item.kind, item.dotted))

            if len(candidates) == 1:
                candidate = next(iter(candidates))

                merged.names[name] = NameInfo(
                    kind=candidate.kind or BindingKind.AMBIGUOUS,
                    dotted=candidate.dotted,
                    taint=taint,
                )
            else:
                merged.names[name] = NameInfo(
                    kind=BindingKind.AMBIGUOUS,
                    taint=taint,
                    candidates=frozenset(candidates),
                )

        return merged
