import ast

from vulnsight.models import Finding
from vulnsight.scanner.taint import TaintAnalyzer

OS_SINKS = {
    "os.system",
    "os.popen",
}

SUBPROCESS_SINKS = {
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}


class CommandInjectionVisitor(ast.NodeVisitor):
    """Find command execution calls receiving potentially tainted data."""

    def __init__(self):
        self.findings = []
        self.taint = TaintAnalyzer()

    def get_command_argument(self, node):
        """Retrieve only the command argument of a sink."""

        if node.args:
            return node.args[0]

        for keyword in node.keywords:
            if keyword.arg in {"args", "command", "cmd"}:
                return keyword.value

        return None

    @staticmethod
    def uses_shell(node):
        """Check whether a subprocess call explicitly enables shell mode."""

        for keyword in node.keywords:
            if keyword.arg == "shell":
                return (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                )

        return False

    def is_shadowed_sink(self, function_node):
        """Check whether a sink name has been reassigned."""

        current = function_node

        while isinstance(current, ast.Attribute):
            current = current.value

        return isinstance(current, ast.Name) and current.id in self.taint.shadowed_names

    def detect_sink(self, node):
        """Check whether a call is a command execution candidate."""

        if self.is_shadowed_sink(node.func):
            return None

        function_name = self.taint.resolve_name(node.func)

        if function_name in OS_SINKS:
            return function_name, self.get_command_argument(node)

        if function_name in SUBPROCESS_SINKS:
            if not self.uses_shell(node):
                return None

            return function_name, self.get_command_argument(node)

        return None

    def add_finding(self, node, function_name):
        """Create a standardized vulnerability finding."""

        self.findings.append(
            Finding(
                function=function_name,
                line=node.lineno,
                cwe="CWE-78",
                severity="Review required",
                message=(
                    f"Potential command injection: tainted data reaches {function_name}"
                ),
                rule_id="PY-CMD-001",
                confidence="medium",
                source="Untrusted input",
                sink=function_name,
            )
        )

    def visit_Import(self, node):
        self.taint.visit_import(node)

    def visit_ImportFrom(self, node):
        self.taint.visit_import_from(node)

    def visit_Assign(self, node):
        """Track normal assignments."""

        self.visit(node.value)
        tainted = self.taint.is_tainted(node.value)

        for target in node.targets:
            self.taint.mark_target(target, tainted)

    def visit_AnnAssign(self, node):
        """Track annotated assignments."""

        if node.value is not None:
            self.visit(node.value)
            self.taint.mark_target(
                node.target,
                self.taint.is_tainted(node.value),
            )

    def visit_AugAssign(self, node):
        """Track augmented assignments."""

        previous_taint = self.taint.is_tainted(node.target)

        self.visit(node.value)
        new_taint = previous_taint or self.taint.is_tainted(node.value)

        self.taint.mark_target(node.target, new_taint)

    def visit_NamedExpr(self, node):
        """Track assignment expressions."""

        self.visit(node.value)
        self.taint.mark_target(
            node.target,
            self.taint.is_tainted(node.value),
        )

    def visit_If(self, node):
        """Analyze both branches and merge their possible taint states."""

        self.visit(node.test)

        initial_state = self.taint.clone()

        self.taint = initial_state.clone()
        for statement in node.body:
            self.visit(statement)
        body_state = self.taint

        self.taint = initial_state.clone()

        for statement in node.orelse:
            self.visit(statement)

        else_state = self.taint

        self.taint = TaintAnalyzer.merge([body_state, else_state])

    def visit_FunctionDef(self, node):
        """Analyze a function using an isolated local taint state."""

        for decorator in node.decorator_list:
            self.visit(decorator)

        for default in node.args.defaults:
            self.visit(default)

        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        parent_state = self.taint
        self.taint = parent_state.clone()

        for statement in node.body:
            self.visit(statement)

        self.taint = parent_state

    def visit_AsyncFunctionDef(self, node):
        """Analyze async functions using isolated local state."""

        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        """Analyze a class body without leaking its assignments outward."""

        for decorator in node.decorator_list:
            self.visit(decorator)

        for base in node.bases:
            self.visit(base)

        parent_state = self.taint
        self.taint = parent_state.clone()

        for statement in node.body:
            self.visit(statement)

        self.taint = parent_state

    def visit_Call(self, node):
        """Detect command execution calls."""

        sink = self.detect_sink(node)

        if sink is not None:
            function_name, command_argument = sink

            if command_argument is not None and self.taint.is_tainted(command_argument):
                self.add_finding(node, function_name)

        self.generic_visit(node)


def scan_source(source_code):
    """Scan Python source code for potential command injection."""

    try:
        tree = ast.parse(source_code)
    except SyntaxError as error:
        raise ValueError(f"Invalid Python source code: {error}") from error

    visitor = CommandInjectionVisitor()
    visitor.visit(tree)

    return visitor.findings


if __name__ == "__main__":
    sample_code = """
import os

filename = input("Enter filename: ")
command = "type " + filename
os.system(command)
"""

    for finding in scan_source(sample_code):
        print(finding.to_dict())
