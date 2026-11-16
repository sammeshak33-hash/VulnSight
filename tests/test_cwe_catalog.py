from vulnsight.cwe.catalog import get_cwe, list_cwes


def test_get_existing_cwe():
    cwe = get_cwe("CWE-78")

    assert cwe is not None
    assert cwe.name == "OS Command Injection"


def test_get_unknown_cwe():
    assert get_cwe("CWE-99999") is None


def test_list_cwes():
    cwes = list_cwes()

    assert "CWE-78" in cwes
    assert "CWE-89" in cwes
    assert len(cwes) >= 8
