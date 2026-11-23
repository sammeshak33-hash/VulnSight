import ast
from dataclasses import dataclass, field, replace

from vulnsight.scanner.policy import TaintPolicy, create_default_policy
from vulnsight.scanner.scope import (
    BindingKind,
    ResolutionCertainty,
    ScopeState,
)
from vulnsight.scanner.specs import GuardDecision, GuardResult, SinkSpec
from vulnsight.scanner.taint_model import (
    Neutralization,
    TaintOrigin,
    TaintValue,
    TraceKind,
    TraceStep,
)

# Methods whose result is text derived from the receiver (for example
# ``value.strip()``). When the receiver is tainted, the result is tainted.
# Predicates and counters (``startswith``, ``isdigit``, ``count``...) and
# unknown or user-defined methods are deliberately not listed.
PROPAGATING_METHODS = frozenset(
    {
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "casefold",
        "title",
        "capitalize",
        "swapcase",
        "replace",
        "format",
        "format_map",
        "join",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "expandtabs",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "translate",
        "removeprefix",
        "removesuffix",
        "encode",
        "decode",
    }
)

# ``get`` and ``copy`` propagate taint only from a receiver that is a source
# container itself: a source the policy declares with ``container=True``
# (``os.environ`` and ``sys.argv`` by default), an alias of one, or a ``copy()``
# of one. See ``_receiver_taint``.
CONTAINER_METHODS = frozenset({"get", "copy"})

# A taint label whose trace holds only these steps is the source value itself:
# it has not passed through a call, an operator or a loop, so it cannot be an
# object built by a user-defined class.
SOURCE_IDENTITY_STEPS = frozenset(
    {
        TraceKind.SOURCE,
        TraceKind.ASSIGN,
        TraceKind.ALIAS,
    }
)


def _user_defined_method_names(tree):
    """Collect method and attribute names defined by classes in this module."""

    names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(item.name)
                elif isinstance(item, ast.Assign):
                    names.update(
                        target.id
                        for target in item.targets
                        if isinstance(target, ast.Name)
                    )
                elif isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    names.add(item.target.id)

    return frozenset(names)


@dataclass(frozen=True, slots=True)
class SinkHit:
    """A tainted argument reaching a configured sink."""

    node: ast.Call
    spec: SinkSpec
    callee: str
    certainty: ResolutionCertainty
    argument_taints: tuple[TaintValue, ...]
    guard: GuardDecision
    scope_kind: str = "module"


@dataclass
class LoopFrame:
    """Control-flow states produced by loop exits."""

    breaks: list[ScopeState] = field(default_factory=list)
    continues: list[ScopeState] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DeferredFunction:
    """A function whose body must be analyzed in its own scope."""

    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
    closure_scope: ScopeState
    closure_kind: str
    qualname: str
    scope_kind: str


class FunctionLocalCollector(ast.NodeVisitor):
    """Collect function-local names without entering nested scopes."""

    def __init__(self):
        self.local_names = set()
        self.global_names = set()
        self.nonlocal_names = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.local_names.add(node.id)

    def visit_Global(self, node):
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocal_names.update(node.names)

    def visit_FunctionDef(self, node):
        self.local_names.add(node.name)

    def visit_AsyncFunctionDef(self, node):
        self.local_names.add(node.name)

    def visit_ClassDef(self, node):
        self.local_names.add(node.name)

    def visit_Lambda(self, node):
        return

    def visit_Import(self, node):
        for alias in node.names:
            self.local_names.add(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != "*":
                self.local_names.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.local_names.add(node.name)

        if node.type:
            self.visit(node.type)

        for statement in node.body:
            self.visit(statement)

    def visit_MatchAs(self, node):
        if node.name:
            self.local_names.add(node.name)

        if node.pattern:
            self.visit(node.pattern)

    def visit_MatchStar(self, node):
        if node.name:
            self.local_names.add(node.name)

    def visit_MatchMapping(self, node):
        if node.rest:
            self.local_names.add(node.rest)

        for pattern in node.patterns:
            self.visit(pattern)

    def _visit_comprehension(self, node):
        # Comprehension iteration targets belong to the comprehension scope.
        # Assignment expressions in filters and result expressions bind
        # in the containing function scope.
        for generator in node.generators:
            self.visit(generator.iter)

            for condition in generator.ifs:
                self.visit(condition)

        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)

    def visit_ListComp(self, node):
        self._visit_comprehension(node)

    def visit_SetComp(self, node):
        self._visit_comprehension(node)

    def visit_DictComp(self, node):
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node):
        self._visit_comprehension(node)


class TaintVisitor(ast.NodeVisitor):
    """Perform conservative, intraprocedural Python taint analysis."""

    def __init__(
        self,
        policy: TaintPolicy | None = None,
        sink_specs: tuple[SinkSpec, ...] = (),
    ):
        self.policy = policy or create_default_policy()
        self.sink_specs = tuple(sink_specs)

        self.scope = ScopeState()
        self.module_scope = self.scope

        self.sink_hits: list[SinkHit] = []
        self.loop_stack: list[LoopFrame] = []
        self._hit_keys = set()

        self.scope_kind = "module"
        self._function_qualname = "<module>"

        self._deferred_functions: list[DeferredFunction] = []
        self._class_outer_scopes = []

        self._global_names = set()
        self._nonlocal_names = set()
        self._closure_scope: ScopeState | None = None
        self._user_method_names = frozenset()

        declared = {item.origin_id for item in self.policy.sources if item.container}
        undeclared = {
            item.origin_id for item in self.policy.sources if not item.container
        }
        self._container_origin_ids = frozenset(declared - undeclared)

    # ---------------------------------------------------------
    # Scope and binding helpers
    # ---------------------------------------------------------

    def _binding_scope(self, name):
        if name in self._global_names:
            return self.module_scope

        if name in self._nonlocal_names:
            if self._closure_scope is not None:
                return self._closure_scope

        return self.scope

    def _bind_name(
        self,
        name,
        kind=BindingKind.VARIABLE,
        dotted=None,
        taint=None,
    ):
        target_scope = self._binding_scope(name)

        target_scope.bind_name(
            name,
            kind=kind,
            dotted=dotted,
            taint=taint,
        )

        if target_scope is not self.scope:
            self.scope.bind_name(
                name,
                kind=kind,
                dotted=dotted,
                taint=taint,
            )

    def _bind_import(self, name, dotted):
        target_scope = self._binding_scope(name)

        target_scope.bind_import(name, dotted)

        if target_scope is not self.scope:
            self.scope.bind_import(name, dotted)

    def _bind_function(self, name):
        self._bind_name(name, kind=BindingKind.FUNCTION)

    def _bind_class(self, name):
        self._bind_name(name, kind=BindingKind.CLASS)

    def _function_closure(self):
        # Methods do not capture the class namespace.
        if self.scope_kind == "class" and self._class_outer_scopes:
            outer_scope, outer_kind = self._class_outer_scopes[-1]
            return outer_scope.copy(), outer_kind

        return self.scope.copy(), self.scope_kind

    def _qualname(self, name):
        if self._function_qualname == "<module>":
            return name

        return f"{self._function_qualname}.{name}"

    @staticmethod
    def _function_arguments(arguments):
        result = (
            list(arguments.posonlyargs)
            + list(arguments.args)
            + list(arguments.kwonlyargs)
        )

        if arguments.vararg is not None:
            result.append(arguments.vararg)

        if arguments.kwarg is not None:
            result.append(arguments.kwarg)

        return result

    # ---------------------------------------------------------
    # Function and class definitions
    # ---------------------------------------------------------

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)

        for default in node.args.defaults:
            self.visit(default)

        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        for argument in self._function_arguments(node.args):
            if argument.annotation is not None:
                self.visit(argument.annotation)

        if node.returns is not None:
            self.visit(node.returns)

        self._bind_function(node.name)

        closure, closure_kind = self._function_closure()

        scope_kind = "method" if self.scope_kind == "class" else "function"

        self._deferred_functions.append(
            DeferredFunction(
                node=node,
                closure_scope=closure,
                closure_kind=closure_kind,
                qualname=self._qualname(node.name),
                scope_kind=scope_kind,
            )
        )

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Lambda(self, node):
        for default in node.args.defaults:
            self.visit(default)

        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        closure, closure_kind = self._function_closure()

        self._deferred_functions.append(
            DeferredFunction(
                node=node,
                closure_scope=closure,
                closure_kind=closure_kind,
                qualname=f"<lambda@{getattr(node, 'lineno', 0)}>",
                scope_kind="lambda",
            )
        )

    def visit_ClassDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)

        for base in node.bases:
            self.visit(base)

        for keyword in node.keywords:
            self.visit(keyword.value)

        outer_scope = self.scope
        outer_kind = self.scope_kind
        outer_qualname = self._function_qualname

        class_scope = outer_scope.copy()

        self._class_outer_scopes.append((outer_scope.copy(), outer_kind))

        self.scope = class_scope
        self.scope_kind = "class"
        self._function_qualname = self._qualname(node.name)

        self.visit_block(node.body)

        self.scope = outer_scope
        self.scope_kind = outer_kind
        self._function_qualname = outer_qualname

        self._class_outer_scopes.pop()

        self._bind_class(node.name)

    def _analyze_deferred_function(self, deferred):
        node = deferred.node

        child = TaintVisitor(
            policy=self.policy,
            sink_specs=self.sink_specs,
        )

        child.scope = deferred.closure_scope.copy()
        child.module_scope = self.module_scope

        child.scope_kind = deferred.scope_kind
        child._function_qualname = deferred.qualname

        child._closure_scope = deferred.closure_scope.copy()

        # Findings are collected centrally.
        child._user_method_names = self._user_method_names

        child.sink_hits = self.sink_hits
        child._hit_keys = self._hit_keys

        child._analyze_function_body(node)

    def _analyze_function_body(self, node):
        arguments = node.args

        collector = FunctionLocalCollector()

        if not isinstance(node, ast.Lambda):
            for statement in node.body:
                collector.visit(statement)

        parameters = self._function_arguments(arguments)
        parameter_names = {argument.arg for argument in parameters}

        self._global_names = collector.global_names
        self._nonlocal_names = collector.nonlocal_names

        # Names assigned anywhere in a function are local throughout
        # that function unless declared global or nonlocal.
        local_names = (
            collector.local_names
            - self._global_names
            - self._nonlocal_names
            - parameter_names
        )

        for name in local_names:
            self.scope.bind_name(name)

        for argument in parameters:
            self._bind_name(
                argument.arg,
                kind=BindingKind.PARAM,
                taint=TaintValue.clean(),
            )

        if isinstance(node, ast.Lambda):
            self.visit(node.body)
        else:
            self.visit_block(node.body)

        # Process nested functions only after this function's body
        # has been analyzed. Their closure must reflect the final
        # enclosing scope, including assignments after their definition.
        self._process_deferred_functions()

    def _process_deferred_functions(self):
        while self._deferred_functions:
            deferred = self._deferred_functions.pop(0)

            if deferred.closure_kind == "function":
                closure = self.scope.copy()
                closure.unreachable = False

                deferred = replace(
                    deferred,
                    closure_scope=closure,
                )

            self._analyze_deferred_function(deferred)

    # ---------------------------------------------------------
    # Expression helpers
    # ---------------------------------------------------------

    @staticmethod
    def _join(values):
        result = TaintValue.clean()

        for value in values:
            result = result.join(value)

        return result

    @staticmethod
    def _step(node, kind, text=""):
        return TraceStep(
            kind=kind,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            text=text,
        )

    @staticmethod
    def _dotted_name(node):
        parts = []
        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if not isinstance(current, ast.Name):
            return ""

        parts.append(current.id)

        return ".".join(reversed(parts))

    def resolve_name(self, node):
        dotted = self._dotted_name(node)

        if not dotted:
            return "", ResolutionCertainty.NONE

        root = dotted.split(".", 1)[0]
        target_scope = self._binding_scope(root)

        return target_scope.resolve_dotted(dotted)

    def _source_for_name(self, name):
        for source in self.policy.sources:
            if name in source.names:
                return source

        return None

    def _source_for_root(self, name):
        for source in self.policy.sources:
            for root in source.roots:
                if name == root or name.startswith(root + "."):
                    return source

        return None

    def _make_source(self, source, node):
        fallback_name = (
            next(iter(source.names | source.roots))
            if source.names or source.roots
            else "unknown-source"
        )

        origin = TaintOrigin(
            origin_id=source.origin_id or fallback_name,
            kind=source.kind,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
        )

        return TaintValue.from_origin(origin)

    def _sanitizer_for_name(self, name):
        for sanitizer in self.policy.sanitizers:
            if name in sanitizer.names:
                return sanitizer

        return None

    def _apply_sanitizer(self, value, sanitizer, node):
        result = value

        step = self._step(
            node,
            TraceKind.PARTIAL_SANITIZER,
            sanitizer.note or "Sanitizer applied",
        )

        if value:
            result = value.with_step(step)

        for cwe in sanitizer.neutralizes:
            neutralization = Neutralization(
                cwe=cwe,
                platforms=frozenset(sanitizer.platforms),
                via=next(iter(sanitizer.names)),
            )

            result = result.neutralized(neutralization)

        return result

    @staticmethod
    def _is_source_identity(label):
        return all(step.kind in SOURCE_IDENTITY_STEPS for step in label.trace)

    def _receiver_taint(self, method, receiver):
        """Return the taint a method call inherits from its receiver.

        The second value is True when the call returns a copy of a source
        container, which stays a source container.

        Only the method name is known, not the receiver's type. ``get`` and
        ``copy`` therefore need a source the policy declares as a container. A
        name that a class in this module also defines (``def strip(self)``)
        propagates only from a receiver that is the source value itself. An
        imported or third-party class with a standard method name cannot be
        told apart from the built-in type.
        """

        if method in CONTAINER_METHODS:
            labels = tuple(
                label
                for label in receiver.labels
                if label.origin.origin_id in self._container_origin_ids
                and self._is_source_identity(label)
            )

            return TaintValue(labels), method == "copy" and bool(labels)

        if method in PROPAGATING_METHODS:
            if method not in self._user_method_names:
                return receiver, False

            return (
                TaintValue(
                    tuple(
                        label
                        for label in receiver.labels
                        if self._is_source_identity(label)
                    )
                ),
                False,
            )

        return TaintValue.clean(), False

    def evaluate(self, node):
        """Evaluate expression taint using an iterative AST traversal."""

        if node is None:
            return TaintValue.clean()

        values = {}
        stack = [(node, False)]

        while stack:
            current, visited = stack.pop()

            if not visited:
                stack.append((current, True))

                for child in reversed(list(ast.iter_child_nodes(current))):
                    stack.append((child, False))

                continue

            children = [values[id(child)] for child in ast.iter_child_nodes(current)]

            result = TaintValue.clean()

            if isinstance(current, ast.Name):
                result = self._binding_scope(current.id).get_taint(current.id)

                resolved, certainty = self.resolve_name(current)

                if certainty != ResolutionCertainty.NONE:
                    source = self._source_for_root(resolved)

                    if source is not None:
                        result = result.join(self._make_source(source, current))

            elif isinstance(current, ast.Attribute):
                resolved, certainty = self.resolve_name(current)

                if certainty != ResolutionCertainty.NONE:
                    source = self._source_for_root(resolved)

                    if source is not None:
                        result = self._make_source(source, current)
                    else:
                        result = values[id(current.value)]

            elif isinstance(current, ast.Subscript):
                resolved, certainty = self.resolve_name(current.value)

                if certainty != ResolutionCertainty.NONE:
                    source = self._source_for_root(resolved)

                    if source is not None:
                        result = self._make_source(source, current)
                    else:
                        result = self._join(children)
                else:
                    result = self._join(children)

            elif isinstance(current, ast.Call):
                callee, certainty = self.resolve_name(current.func)
                source = None

                if certainty != ResolutionCertainty.NONE:
                    source = self._source_for_name(callee)

                if source is not None:
                    result = self._make_source(source, current)
                else:
                    argument_values = [
                        values[id(argument)] for argument in current.args
                    ]

                    argument_values.extend(
                        values[id(keyword.value)] for keyword in current.keywords
                    )

                    container_copy = False

                    if isinstance(current.func, ast.Attribute):
                        receiver_taint, container_copy = self._receiver_taint(
                            current.func.attr,
                            values[id(current.func.value)],
                        )
                        argument_values.append(receiver_taint)

                    result = self._join(argument_values)

                    sanitizer = None

                    if certainty == ResolutionCertainty.DEFINITE:
                        sanitizer = self._sanitizer_for_name(callee)

                    if sanitizer is not None:
                        result = self._apply_sanitizer(
                            result,
                            sanitizer,
                            current,
                        )

                    elif container_copy:
                        result = result.with_step(
                            self._step(current, TraceKind.ALIAS, "copy")
                        )

                    elif result:
                        result = result.with_step(
                            self._step(
                                current,
                                TraceKind.CALL,
                                callee or "unknown call",
                            )
                        )

            elif isinstance(current, ast.BinOp):
                result = self._join(children)

                if result:
                    result = result.with_step(
                        self._step(
                            current,
                            TraceKind.CONCAT,
                            "Expression",
                        )
                    )

            elif isinstance(current, ast.JoinedStr):
                result = self._join(children)

                if result:
                    result = result.with_step(
                        self._step(
                            current,
                            TraceKind.FORMAT,
                            "F-string",
                        )
                    )

            elif isinstance(current, ast.FormattedValue):
                result = self._join(children)

                if result:
                    result = result.with_step(
                        self._step(
                            current,
                            TraceKind.FORMAT,
                            "Formatted value",
                        )
                    )

            elif isinstance(current, ast.Constant):
                result = TaintValue.clean()

            else:
                result = self._join(children)

            values[id(current)] = result

        return values[id(node)]

    # ---------------------------------------------------------
    # Assignment helpers
    # ---------------------------------------------------------

    def bind_target(self, target, taint):
        if isinstance(target, ast.Name):
            self._bind_name(target.id, taint=taint)

        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind_target(element, taint)

        elif isinstance(target, ast.Starred):
            self.bind_target(target.value, taint)

        elif isinstance(target, ast.MatchAs):
            if target.name:
                self._bind_name(target.name, taint=taint)

        elif isinstance(target, ast.MatchStar):
            if target.name:
                self._bind_name(target.name, taint=taint)

    def visit_Assign(self, node):
        self.visit(node.value)
        taint = self.evaluate(node.value)

        for target in node.targets:
            self.bind_target(target, taint)

            if not isinstance(target, ast.Name):
                self.visit(target)

    def visit_AnnAssign(self, node):
        self.visit(node.annotation)

        if node.value is not None:
            self.visit(node.value)
            self.bind_target(
                node.target,
                self.evaluate(node.value),
            )

    def visit_AugAssign(self, node):
        previous = self.evaluate(node.target)

        self.visit(node.value)
        current = self.evaluate(node.value)

        result = previous.join(current)

        if result:
            result = result.with_step(
                self._step(
                    node,
                    TraceKind.ASSIGN,
                    "Augmented assignment",
                )
            )

        self.bind_target(node.target, result)

    def visit_NamedExpr(self, node):
        self.visit(node.value)

        self.bind_target(
            node.target,
            self.evaluate(node.value),
        )

    # ---------------------------------------------------------
    # Imports
    # ---------------------------------------------------------

    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname:
                local_name = alias.asname
                dotted = alias.name
            else:
                local_name = alias.name.split(".")[0]
                dotted = local_name

            self._bind_import(local_name, dotted)

    def visit_ImportFrom(self, node):
        module = node.module or ""

        for alias in node.names:
            if alias.name == "*":
                continue

            local_name = alias.asname or alias.name
            dotted = f"{module}.{alias.name}".strip(".")

            self._bind_import(local_name, dotted)

    # ---------------------------------------------------------
    # Branches
    # ---------------------------------------------------------

    def visit_If(self, node):
        self.visit(node.test)

        initial = self.scope.copy()

        self.scope = initial.copy()
        self.visit_block(node.body)
        body_state = self.scope

        self.scope = initial.copy()
        self.visit_block(node.orelse)
        else_state = self.scope

        self.scope = ScopeState.join([body_state, else_state])

    def visit_block(self, statements):
        for statement in statements:
            if self.scope.unreachable:
                break

            self.visit(statement)

    # ---------------------------------------------------------
    # Loops
    # ---------------------------------------------------------

    def _visit_loop(self, node, target=None, iterable=None):
        if iterable is not None:
            self.visit(iterable)
            iterable_taint = self.evaluate(iterable)
        else:
            iterable_taint = TaintValue.clean()

        initial = self.scope.copy()
        frame = LoopFrame()

        self.loop_stack.append(frame)
        self.scope = initial.copy()

        if target is not None:
            loop_taint = iterable_taint

            if loop_taint:
                loop_taint = loop_taint.with_step(
                    self._step(
                        node,
                        TraceKind.LOOP,
                        "Loop iteration",
                    )
                )

            self.bind_target(target, loop_taint)

        self.visit_block(node.body)
        body_state = self.scope

        self.loop_stack.pop()

        # Paths that can complete the loop normally.
        normal_paths = [initial]

        if not body_state.unreachable:
            normal_paths.append(body_state)

        normal_paths.extend(frame.continues)

        normal_state = ScopeState.join(normal_paths)

        # A loop's else block executes only after normal completion.
        # Break paths must never enter this block.
        if node.orelse:
            self.scope = normal_state.copy()
            self.visit_block(node.orelse)
            normal_state = self.scope

        # Merge normal completion with paths that exited using break.
        final_paths = []

        if not normal_state.unreachable:
            final_paths.append(normal_state)

        final_paths.extend(frame.breaks)

        if final_paths:
            self.scope = ScopeState.join(final_paths)
        else:
            self.scope = normal_state

    def visit_For(self, node):
        self._visit_loop(
            node,
            target=node.target,
            iterable=node.iter,
        )

    def visit_AsyncFor(self, node):
        self._visit_loop(
            node,
            target=node.target,
            iterable=node.iter,
        )

    def visit_While(self, node):
        self.visit(node.test)
        self._visit_loop(node)

    def visit_Break(self, node):
        if self.loop_stack:
            self.loop_stack[-1].breaks.append(self.scope.copy())

        self.scope.unreachable = True

    def visit_Continue(self, node):
        if self.loop_stack:
            self.loop_stack[-1].continues.append(self.scope.copy())

        self.scope.unreachable = True

    # ---------------------------------------------------------
    # Exception handling
    # ---------------------------------------------------------

    def visit_Try(self, node):
        initial = self.scope.copy()
        exception_states = [initial]

        for statement in node.body:
            if self.scope.unreachable:
                break

            self.visit(statement)
            exception_states.append(self.scope.copy())

        normal_state = self.scope
        normal_paths = []

        if not normal_state.unreachable:
            self.scope = normal_state.copy()
            self.visit_block(node.orelse)
            normal_paths.append(self.scope)

        exception_base = ScopeState.join(exception_states)
        exception_paths = []

        for handler in node.handlers:
            self.scope = exception_base.copy()

            if handler.type is not None:
                self.visit(handler.type)

            if handler.name:
                self._bind_name(handler.name)

            self.visit_block(handler.body)
            exception_paths.append(self.scope)

        paths = normal_paths + exception_paths

        if not paths:
            paths = [normal_state]

        self.scope = ScopeState.join(paths)

        if node.finalbody:
            pending_exit = self.scope.unreachable

            self.scope.unreachable = False
            self.visit_block(node.finalbody)

            if pending_exit and not self.scope.unreachable:
                self.scope.unreachable = True

    def visit_TryStar(self, node):
        self.visit_Try(node)

    def visit_Raise(self, node):
        if node.exc is not None:
            self.visit(node.exc)

        if node.cause is not None:
            self.visit(node.cause)

        self.scope.unreachable = True

    # ---------------------------------------------------------
    # Pattern matching
    # ---------------------------------------------------------

    def _bind_pattern(self, pattern, taint):
        if isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None:
                self._bind_pattern(pattern.pattern, taint)

            if pattern.name:
                self._bind_name(pattern.name, taint=taint)

        elif isinstance(pattern, ast.MatchStar):
            if pattern.name:
                self._bind_name(pattern.name, taint=taint)

        elif isinstance(pattern, ast.MatchMapping):
            for child in pattern.patterns:
                self._bind_pattern(child, taint)

            if pattern.rest:
                self._bind_name(pattern.rest, taint=taint)

        elif isinstance(pattern, ast.MatchSequence):
            for child in pattern.patterns:
                self._bind_pattern(child, taint)

        elif isinstance(pattern, ast.MatchClass):
            for child in pattern.patterns:
                self._bind_pattern(child, taint)

            for child in pattern.kwd_patterns:
                self._bind_pattern(child, taint)

        elif isinstance(pattern, ast.MatchOr):
            for child in pattern.patterns:
                self._bind_pattern(child, taint)

    @staticmethod
    def _irrefutable_pattern(pattern):
        if isinstance(pattern, ast.MatchAs):
            return pattern.pattern is None or (
                pattern.name is not None
                and TaintVisitor._irrefutable_pattern(pattern.pattern)
            )

        if isinstance(pattern, ast.MatchOr):
            return any(
                TaintVisitor._irrefutable_pattern(item) for item in pattern.patterns
            )

        return False

    def visit_Match(self, node):
        self.visit(node.subject)

        subject_taint = self.evaluate(node.subject)
        initial = self.scope.copy()

        paths = []
        has_irrefutable_case = False

        for case in node.cases:
            self.scope = initial.copy()

            self._bind_pattern(
                case.pattern,
                subject_taint,
            )

            if case.guard is not None:
                self.visit(case.guard)

            self.visit_block(case.body)
            paths.append(self.scope)

            if case.guard is None and self._irrefutable_pattern(case.pattern):
                has_irrefutable_case = True

        if not has_irrefutable_case:
            paths.append(initial)

        self.scope = ScopeState.join(paths)

    # ---------------------------------------------------------
    # Context managers
    # ---------------------------------------------------------

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)

            if item.optional_vars is not None:
                # The value bound by "as" comes from __enter__ or
                # __aenter__, not necessarily from the context expression.
                # Until context-manager return values are modeled, keep it clean.
                self.bind_target(
                    item.optional_vars,
                    TaintValue.clean(),
                )

        self.visit_block(node.body)

    def visit_AsyncWith(self, node):
        self.visit_With(node)

    # ---------------------------------------------------------
    # Sink detection
    # ---------------------------------------------------------

    @staticmethod
    def _select_arguments(node, spec):
        selected = []

        for position in spec.selector.positions:
            if position < len(node.args):
                selected.append(node.args[position])

        for keyword in node.keywords:
            if keyword.arg in spec.selector.keywords:
                selected.append(keyword.value)

        return selected

    def _record_sink(self, node, spec, callee, certainty):
        arguments = self._select_arguments(node, spec)

        taints = tuple(self.evaluate(argument) for argument in arguments)

        if not any(taints):
            return

        decision = (
            spec.guard(node)
            if spec.guard is not None
            else GuardDecision(GuardResult.APPLIES)
        )

        if decision.result == GuardResult.NOT_APPLICABLE:
            return

        key = (
            spec.rule_id,
            node.lineno,
            node.col_offset,
        )

        if key in self._hit_keys:
            return

        self._hit_keys.add(key)

        self.sink_hits.append(
            SinkHit(
                node=node,
                spec=spec,
                callee=callee,
                certainty=certainty,
                argument_taints=taints,
                guard=decision,
                scope_kind=self.scope_kind,
            )
        )

    def visit_Call(self, node):
        callee, certainty = self.resolve_name(node.func)

        if certainty != ResolutionCertainty.NONE:
            for spec in self.sink_specs:
                if callee in spec.names:
                    self._record_sink(
                        node,
                        spec,
                        callee,
                        certainty,
                    )

        self.generic_visit(node)

    # ---------------------------------------------------------
    # Other control-flow exits
    # ---------------------------------------------------------

    def visit_Return(self, node):
        if node.value is not None:
            self.visit(node.value)

        self.scope.unreachable = True

    def visit_Assert(self, node):
        self.visit(node.test)

        if node.msg is not None:
            self.visit(node.msg)

    # ---------------------------------------------------------
    # Public interface
    # ---------------------------------------------------------

    def analyze(self, tree):
        """Analyze a module and all deferred function bodies."""

        if not isinstance(tree, ast.Module):
            raise TypeError("TaintVisitor.analyze expects an ast.Module")

        self._user_method_names = _user_defined_method_names(tree)

        self.visit_block(tree.body)

        # Functions use the completed module namespace.
        self.module_scope = self.scope

        self._process_deferred_functions()

        return tuple(self.sink_hits)


def analyze_source(
    source,
    sink_specs=(),
    policy=None,
    filename="<unknown>",
):
    """Parse and analyze Python source code."""

    tree = ast.parse(
        source,
        filename=filename,
    )

    visitor = TaintVisitor(
        policy=policy,
        sink_specs=tuple(sink_specs),
    )

    return visitor.analyze(tree)
