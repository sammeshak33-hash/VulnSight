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

    @staticmethod
    def get_function_name(node):
        """Convert a function expression into a dotted name."""

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = CommandInjectionVisitor.get_function_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr

        return ""

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

    def detect_sink(self, node):
        """Check whether a call is a command injection candidate."""

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
        """Track normal variable assignments."""

        self.generic_visit(node.value)

        tainted = self.taint.is_tainted(node.value)

        for target in node.targets:
            self.taint.mark_target(target, tainted)

    def visit_AnnAssign(self, node):
        """Track annotated variable assignments."""

        if node.value is not None:
            self.generic_visit(node.value)

            self.taint.mark_target(
                node.target,
                self.taint.is_tainted(node.value),
            )

    def visit_AugAssign(self, node):
        """Track augmented assignments such as command += input()."""

        previous_taint = self.taint.is_tainted(node.target)

        self.generic_visit(node.value)

        new_taint = previous_taint or self.taint.is_tainted(node.value)

        self.taint.mark_target(node.target, new_taint)

    def visit_Call(self, node):
        """Detect command execution sinks."""

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
