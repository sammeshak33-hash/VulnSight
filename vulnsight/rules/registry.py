from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """Represent a vulnerability detection rule."""

    rule_id: str
    name: str
    cwe: str
    language: str
    description: str


class RuleRegistry:
    """Register and retrieve vulnerability detection rules."""

    def __init__(self):
        self._rules = {}

    def register(self, rule):
        """Register a new rule."""

        if rule.rule_id in self._rules:
            raise ValueError(f"Rule already registered: {rule.rule_id}")

        self._rules[rule.rule_id] = rule

    def get(self, rule_id):
        """Retrieve a rule by its identifier."""

        return self._rules.get(rule_id)

    def list_rules(self):
        """Return all registered rules."""

        return tuple(self._rules.values())

    def __len__(self):
        return len(self._rules)
