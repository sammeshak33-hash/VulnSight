import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class CWEInfo:
    """Store information about a Common Weakness Enumeration."""

    cwe_id: str
    name: str
    description: str
    category: str
    severity_guidance: str


@lru_cache(maxsize=1)
def load_catalog():
    """Load the CWE catalog from its JSON file."""

    catalog_path = Path(__file__).with_name("catalog.json")

    with catalog_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_cwe(cwe_id):
    """Retrieve information about a CWE identifier."""

    data = load_catalog().get(cwe_id)

    if data is None:
        return None

    return CWEInfo(
        cwe_id=cwe_id,
        name=data["name"],
        description=data["description"],
        category=data["category"],
        severity_guidance=data["severity_guidance"],
    )


def list_cwes():
    """Return all available CWE identifiers."""

    return tuple(sorted(load_catalog()))
