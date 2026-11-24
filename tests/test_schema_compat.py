"""Schema version contract for the 2.0 to 2.1 change (M1.3).

* 2.0 documents without parameter evidence stay readable.
* 2.0 documents that contain ``SourceKind.PARAMETER`` are rejected.
* 2.1 documents are readable with or without parameter evidence.
* Any other version is rejected.
"""

import ast
import json

import pytest

from tests.test_serialization import golden_data, read_golden
from vulnsight.codec import SchemaError
from vulnsight.scan_result import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    ScanResult,
    ScanStatus,
)
from vulnsight.scanner.command_injection import detect
from vulnsight.scanner.policy import ParameterMode, create_default_policy
from vulnsight.scanner.taint_model import SourceKind

RECALL = create_default_policy(ParameterMode.RECALL)

PARAMETER_SOURCE = """
import os

def f(a):
    os.system(input())
    os.system(a)
"""

MIXED_SOURCE = """
import os

def f(a):
    os.system(a + input())
"""


def parameter_result(source=PARAMETER_SOURCE):
    findings = detect(ast.parse(source), policy=RECALL)

    return ScanResult(status=ScanStatus.COMPLETE, findings=findings)


def parameter_data(version, source=PARAMETER_SOURCE):
    data = parameter_result(source).to_dict()
    data["schema_version"] = version

    return data


def kinds(result):
    return {
        label.origin.kind for finding in result.findings for label in finding.evidence
    }


def test_the_constants_describe_the_contract():
    assert SCHEMA_VERSION == "2.1"
    assert SUPPORTED_SCHEMA_VERSIONS == {"2.0", "2.1"}


def test_the_fixture_really_contains_parameter_evidence():
    assert SourceKind.PARAMETER in kinds(parameter_result())


# -- 1. 2.0 without parameter evidence stays readable --------------


def test_golden_data_labelled_2_0_is_readable():
    data = golden_data()
    data["schema_version"] = "2.0"

    loaded = ScanResult.from_dict(data)

    assert SourceKind.PARAMETER not in kinds(loaded)
    assert loaded.schema_version == "2.1"


def test_golden_text_labelled_2_0_is_readable_through_json():
    text = read_golden().replace('"schema_version": "2.1"', '"schema_version": "2.0"')

    assert '"schema_version": "2.0"' in text
    assert ScanResult.from_json(text).findings


def test_a_2_0_document_with_only_real_source_evidence_is_readable():
    data = parameter_data("2.0", "import os\nos.system(input())\n")

    assert SourceKind.PARAMETER not in kinds(ScanResult.from_dict(data))


def test_a_2_0_document_with_no_findings_is_readable():
    data = ScanResult(status=ScanStatus.COMPLETE).to_dict()
    data["schema_version"] = "2.0"

    assert ScanResult.from_dict(data).findings == ()


# -- 2. 2.0 with parameter evidence is rejected --------------------


def test_a_2_0_document_with_parameter_evidence_is_rejected():
    with pytest.raises(SchemaError, match="parameter"):
        ScanResult.from_dict(parameter_data("2.0"))


def test_the_rejection_is_a_value_error():
    with pytest.raises(ValueError):
        ScanResult.from_dict(parameter_data("2.0"))


def test_the_rejection_message_names_the_path_value_and_versions():
    with pytest.raises(SchemaError) as error:
        ScanResult.from_dict(parameter_data("2.0"))

    message = str(error.value)

    assert "findings[" in message
    assert "evidence[" in message
    assert "origin.kind" in message
    assert "'parameter'" in message
    assert "'2.1'" in message
    assert "'2.0'" in message


def test_the_rejection_points_at_the_first_offending_evidence_item():
    # The first finding (line 5) has a real source; the second has a parameter.
    with pytest.raises(SchemaError, match=r"findings\[1\]\.evidence\[0\]"):
        ScanResult.from_dict(parameter_data("2.0"))


def test_a_2_0_document_with_mixed_evidence_is_rejected():
    with pytest.raises(SchemaError, match="parameter"):
        ScanResult.from_dict(parameter_data("2.0", MIXED_SOURCE))


def test_the_rejection_also_applies_to_json_text():
    text = json.dumps(parameter_data("2.0"))

    with pytest.raises(SchemaError, match="parameter"):
        ScanResult.from_json(text)


def test_relabelling_a_2_1_document_as_2_0_is_what_gets_rejected():
    text = parameter_result().to_json()

    assert '"schema_version": "2.1"' in text

    old = text.replace('"schema_version": "2.1"', '"schema_version": "2.0"')

    with pytest.raises(SchemaError, match="parameter"):
        ScanResult.from_json(old)


# -- 3. 2.1 is readable with or without parameter evidence ---------


def test_a_2_1_document_with_parameter_evidence_is_readable():
    result = parameter_result()
    loaded = ScanResult.from_dict(parameter_data("2.1"))

    assert loaded == result
    assert SourceKind.PARAMETER in kinds(loaded)


def test_a_2_1_document_with_mixed_evidence_is_readable():
    loaded = ScanResult.from_dict(parameter_data("2.1", MIXED_SOURCE))

    assert kinds(loaded) == {SourceKind.PARAMETER, SourceKind.INTERACTIVE}


def test_the_golden_file_is_2_1_and_readable_without_parameter_evidence():
    loaded = ScanResult.from_json(read_golden())

    assert json.loads(read_golden())["schema_version"] == "2.1"
    assert SourceKind.PARAMETER not in kinds(loaded)


def test_the_writer_always_writes_2_1():
    assert parameter_result().to_dict()["schema_version"] == "2.1"
    assert (
        ScanResult.from_dict(parameter_data("2.0", "x = 1\n")).to_dict()[
            "schema_version"
        ]
        == "2.1"
    )


def test_a_2_0_document_rewritten_is_a_2_1_document_that_round_trips():
    data = golden_data()
    data["schema_version"] = "2.0"

    rewritten = ScanResult.from_dict(data).to_json()

    assert '"schema_version": "2.1"' in rewritten
    assert ScanResult.from_json(rewritten).to_json() == rewritten


# -- 4. Other versions are still rejected --------------------------


@pytest.mark.parametrize("version", ["1.0", "2.2", "3.0", "2", "2.00", " 2.1", ""])
@pytest.mark.parametrize("with_parameters", [False, True])
def test_unsupported_versions_are_rejected(version, with_parameters):
    data = parameter_data(version) if with_parameters else golden_data()
    data["schema_version"] = version

    with pytest.raises(SchemaError, match="schema_version"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("version", [2, 2.1, None, ["2.1"]])
def test_non_string_versions_are_rejected(version):
    data = golden_data()
    data["schema_version"] = version

    with pytest.raises(SchemaError, match="schema_version"):
        ScanResult.from_dict(data)
