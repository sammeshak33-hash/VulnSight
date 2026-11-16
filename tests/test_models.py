from vulnsight.models import Finding


def test_finding_creation():
    finding = Finding(
        function="os.system",
        line=5,
        cwe="CWE-78",
        severity="Review required",
        message="Potential command injection",
    )

    assert finding.function == "os.system"
    assert finding.line == 5
    assert finding.cwe == "CWE-78"


def test_finding_dictionary_conversion():
    finding = Finding(
        function="os.system",
        line=5,
        cwe="CWE-78",
        severity="Review required",
        message="Potential command injection",
    )

    data = finding.to_dict()

    assert data["function"] == "os.system"
    assert data["cwe"] == "CWE-78"


def test_finding_supports_dictionary_access():
    finding = Finding(
        function="os.system",
        line=5,
        cwe="CWE-78",
        severity="Review required",
        message="Potential command injection",
    )

    assert finding["function"] == "os.system"
    assert finding.get("unknown", "default") == "default"
