import ast

SOURCE_CALLS = {
    "input",
    "builtins.input",
    "sys.stdin.read",
    "sys.stdin.readline",
    "os.getenv",
}

SOURCE_ROOTS = {
    "sys.argv",
    "os.environ",
}

SANITIZER_CALLS = {
    "int",
    "float",
    "bool",
    "len",
    "shlex.quote",
}


class TaintAnalyzer:
    """Track potentially untrusted data within a Python scope."""

    def __init__(self):
        self.tainted_variables = set()
        self.aliases = {}
        self.shadowed_names = set()

    def clone(self):
        """Create an independent copy of the current analysis state."""

        cloned = TaintAnalyzer()
        cloned.tainted_variables = self.tainted_variables.copy()
        cloned.aliases = self.aliases.copy()
        cloned.shadowed_names = self.shadowed_names.copy()
        return cloned

    @staticmethod
    def merge(states):
        """Merge branch states conservatively."""

        if not states:
            return TaintAnalyzer()

        merged = TaintAnalyzer()

        for state in states:
            merged.tainted_variables.update(state.tainted_variables)
            merged.shadowed_names.update(state.shadowed_names)

        common_aliases = states[0].aliases.copy()

        for state in states[1:]:
            common_aliases = {
                name: value
                for name, value in common_aliases.items()
                if state.aliases.get(name) == value
            }

        merged.aliases = common_aliases
        return merged

    def resolve_name(self, node):
        """Resolve names and imported aliases into dotted names."""

        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            parent = self.resolve_name(node.value)

            if parent:
                return f"{parent}.{node.attr}"

        return ""

    def is_tainted(self, node):
        """Determine whether an expression contains potentially tainted data."""

        if isinstance(node, ast.Name):
            return (
                node.id in self.tainted_variables
                or self.resolve_name(node) in SOURCE_ROOTS
            )

        if isinstance(node, ast.Constant):
            return False

        if isinstance(node, ast.Subscript):
            base_name = self.resolve_name(node.value)

            if base_name in SOURCE_ROOTS:
                return True

            return self.is_tainted(node.value) or self.is_tainted(node.slice)

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.shadowed_names:
                function_name = ""
            else:
                function_name = self.resolve_name(node.func)

            if function_name in SOURCE_CALLS:
                return True

            if function_name in SANITIZER_CALLS:
                return False

            if isinstance(node.func, ast.Attribute):
                if self.is_tainted(node.func.value):
                    return True

            return any(self.is_tainted(arg) for arg in node.args) or any(
                self.is_tainted(keyword.value) for keyword in node.keywords
            )

        if isinstance(node, ast.Attribute):
            if self.resolve_name(node) in SOURCE_ROOTS:
                return True

            return self.is_tainted(node.value)

        if isinstance(node, ast.Lambda):
            return self.is_tainted(node.body)

        if isinstance(node, ast.NamedExpr):
            return self.is_tainted(node.value)

        return any(self.is_tainted(child) for child in ast.iter_child_nodes(node))

    def mark_target(self, target, tainted):
        """Update taint and alias information for assignment targets."""

        if isinstance(target, ast.Name):
            self.aliases.pop(target.id, None)
            self.shadowed_names.add(target.id)

            if tainted:
                self.tainted_variables.add(target.id)
            else:
                self.tainted_variables.discard(target.id)

        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.mark_target(element, tainted)

    def visit_import(self, node):
        """Record normal Python import aliases."""

        for alias in node.names:
            if alias.asname:
                imported_name = alias.asname
                imported_module = alias.name
            else:
                imported_name = alias.name.split(".")[0]
                imported_module = imported_name

            self.aliases[imported_name] = imported_module
            self.shadowed_names.discard(imported_name)
            self.tainted_variables.discard(imported_name)

    def visit_import_from(self, node):
        """Record names imported directly from a module."""

        module = node.module or ""

        for alias in node.names:
            if alias.name == "*":
                continue

            imported_name = alias.asname or alias.name
            self.aliases[imported_name] = f"{module}.{alias.name}"
            self.shadowed_names.discard(imported_name)
            self.tainted_variables.discard(imported_name)
