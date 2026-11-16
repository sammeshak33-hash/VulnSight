from vulnsight.rules.registry import Rule, RuleRegistry


def create_default_registry():
    """Create the registry containing initial VulnSight rules."""

    registry = RuleRegistry()

    registry.register(
        Rule(
            rule_id="PY-CMD-001",
            name="Python OS Command Injection",
            cwe="CWE-78",
            language="python",
            description=(
                "Detects potentially tainted data reaching "
                "shell command execution functions."
            ),
        )
    )

    return registry


__all__ = [
    "Rule",
    "RuleRegistry",
    "create_default_registry",
]
