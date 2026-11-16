from dataclasses import asdict, dataclass


@dataclass
class Finding:
    """Represent a potential security vulnerability."""

    function: str
    line: int
    cwe: str
    severity: str
    message: str

    rule_id: str = ""
    confidence: str = "medium"
    source: str = ""
    sink: str = ""

    def to_dict(self):
        """Convert the finding into a dictionary."""
        return asdict(self)

    def __getitem__(self, key):
        """Support dictionary-style access for compatibility."""
        return getattr(self, key)

    def get(self, key, default=None):
        """Provide dictionary-style get access."""
        return getattr(self, key, default)
