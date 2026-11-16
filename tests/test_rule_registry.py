import pytest

from vulnsight.rules import create_default_registry
from vulnsight.rules.registry import Rule, RuleRegistry


def test_default_registry_contains_command_injection():
    registry = create_default_registry()

    rule = registry.get("PY-CMD-001")

    assert rule is not None
    assert rule.cwe == "CWE-78"
    assert rule.language == "python"


def test_register_new_rule():
    registry = RuleRegistry()

    rule = Rule(
        rule_id="PY-SQL-001",
        name="Python SQL Injection",
        cwe="CWE-89",
        language="python",
        description="Detects unsafe SQL query construction.",
    )

    registry.register(rule)

    assert registry.get("PY-SQL-001") == rule


def test_duplicate_rule_registration():
    registry = create_default_registry()

    duplicate = Rule(
        rule_id="PY-CMD-001",
        name="Duplicate Rule",
        cwe="CWE-78",
        language="python",
        description="Duplicate.",
    )

    with pytest.raises(ValueError):
        registry.register(duplicate)


def test_list_registered_rules():
    registry = create_default_registry()

    assert len(registry.list_rules()) == 1
    assert len(registry) == 1
