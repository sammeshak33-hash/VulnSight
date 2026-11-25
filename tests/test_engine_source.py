"""ScanEngine.scan_source: in-memory scanning and the failure contract."""

import warnings
from types import SimpleNamespace

import pytest

from tests.differential_corpus import CASES
from vulnsight import engine as engine_module
from vulnsight.engine import (
    ANALYSIS_ERROR,
    ENCODING_ERROR,
    SYNTAX_ERROR,
    ScanEngine,
    installed_version,
    is_link_like,
)
from vulnsight.findings import ConfidenceLevel
from vulnsight.scan_result import IssueLevel, ScanResult, ScanStatus
from vulnsight.scanner import command_injection
from vulnsight.scanner.policy import ParameterMode
from vulnsight.scanner.taint_model import SourceKind

VULNERABLE = "import os\nos.system(input())\n"
PARAMETER_CODE = "import os\ndef run(cmd):\n    os.system(cmd)\n"

STRICT = ScanEngine()
RECALL = ScanEngine(parameter_mode=ParameterMode.RECALL)


def codes(result):
    return [issue.code for issue in result.issues]


# -- construction ---------------------------------------------------


def test_the_default_mode_is_strict():
    assert STRICT.parameter_mode is ParameterMode.STRICT


@pytest.mark.parametrize("mode", ["strict", "recall", None, 1])
def test_a_non_enum_mode_is_rejected(mode):
    with pytest.raises(ValueError, match="parameter_mode"):
        ScanEngine(parameter_mode=mode)


# -- findings -------------------------------------------------------


def test_a_vulnerable_source_gives_a_complete_result_with_a_finding():
    result = STRICT.scan_source(VULNERABLE)

    assert result.status is ScanStatus.COMPLETE
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "PY-CMD-001"
    assert result.issues == ()


def test_a_clean_source_gives_a_complete_empty_result():
    result = STRICT.scan_source("x = 1\n")

    assert result.status is ScanStatus.COMPLETE
    assert result.findings == ()
    assert result.metadata.files_scanned == 1


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_the_engine_matches_the_detector_for_every_corpus_case(case):
    expected = command_injection.scan_source(case.source)

    assert list(STRICT.scan_source(case.source).findings) == expected


def test_bytes_and_str_give_the_same_result():
    assert STRICT.scan_source(VULNERABLE.encode()) == STRICT.scan_source(VULNERABLE)


# -- parameter mode -------------------------------------------------


def test_strict_mode_leaves_parameters_clean():
    assert STRICT.scan_source(PARAMETER_CODE).findings == ()


def test_recall_mode_taints_parameters_with_low_confidence():
    result = RECALL.scan_source(PARAMETER_CODE)

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.confidence is ConfidenceLevel.LOW
    assert finding.evidence[0].origin.kind is SourceKind.PARAMETER


@pytest.mark.parametrize(("engine", "value"), [(STRICT, "strict"), (RECALL, "recall")])
def test_the_mode_is_recorded_in_the_settings_of_every_result(engine, value):
    for source in ("x = 1\n", "def (:\n", PARAMETER_CODE):
        result = engine.scan_source(source)

        assert result.metadata.settings_dict() == {"parameter_mode": value}


# -- in-memory placeholders ----------------------------------------


def test_without_a_file_name_the_location_file_is_none():
    result = STRICT.scan_source(VULNERABLE)

    assert result.findings[0].location.file is None
    assert result.target is None


def test_a_supplied_file_name_is_recorded_normalized():
    result = STRICT.scan_source(VULNERABLE, file="pkg\\mod.py")

    assert result.findings[0].location.file == "pkg/mod.py"
    assert result.target is None


def test_the_file_name_is_never_opened(tmp_path):
    result = STRICT.scan_source(VULNERABLE, file=str(tmp_path / "missing.py"))

    assert result.status is ScanStatus.COMPLETE


def test_issues_for_in_memory_source_have_no_file_unless_one_is_given():
    assert STRICT.scan_source("def (:\n").issues[0].file is None
    assert STRICT.scan_source("def (:\n", file="a.py").issues[0].file == "a.py"


def test_file_is_keyword_only():
    with pytest.raises(TypeError):
        STRICT.scan_source(VULNERABLE, "a.py")


def test_files_scanned_is_one_for_success_and_zero_for_failure():
    assert STRICT.scan_source("x = 1\n").metadata.files_scanned == 1
    assert STRICT.scan_source("def (:\n").metadata.files_scanned == 0


# -- failures are returned, not raised -----------------------------


def test_a_syntax_error_is_an_error_issue_and_a_failed_scan():
    result = STRICT.scan_source("x = 1\ndef (:\n")

    assert result.status is ScanStatus.FAILED
    assert result.findings == ()
    assert codes(result) == [SYNTAX_ERROR]
    assert result.issues[0].level is IssueLevel.ERROR
    assert result.issues[0].line == 2


def test_a_null_byte_is_a_syntax_error_issue():
    for source in ("x = 1\x00\n", b"x = 1\x00\n"):
        result = STRICT.scan_source(source)

        assert codes(result) == [SYNTAX_ERROR]
        assert result.status is ScanStatus.FAILED


@pytest.mark.parametrize(
    "source",
    [
        b"x = '\xff'\n",
        b"# coding: no-such-encoding\nx = 1\n",
        b"\xef\xbb\xbf# coding: latin-1\nx = 1\n",
        b"# coding: ascii\nx = '\xe9'\n",
    ],
    ids=["bad-utf8", "unknown-encoding", "bom-conflict", "ascii-declared"],
)
def test_bad_encodings_are_encoding_error_issues(source):
    result = STRICT.scan_source(source)

    assert codes(result) == [ENCODING_ERROR]
    assert result.status is ScanStatus.FAILED
    assert result.metadata.files_scanned == 0


@pytest.mark.parametrize(
    "source",
    [
        b"\xef\xbb\xbfimport os\nos.system(input())\n",
        b"# -*- coding: latin-1 -*-\nx = '\xe9'\nimport os\nos.system(input())\n",
        b"import os\r\nos.system(input())\r\n",
    ],
    ids=["bom", "latin-1", "crlf"],
)
def test_valid_encodings_are_analysed(source):
    result = STRICT.scan_source(source)

    assert result.status is ScanStatus.COMPLETE
    assert len(result.findings) == 1


def test_a_recursion_error_while_analysing_is_an_analysis_error_issue():
    chain = "+".join(["a"] * 900)
    source = f"import os\na = input()\nos.system({chain})\n"
    result = STRICT.scan_source(source, file="deep.py")

    assert codes(result) == [ANALYSIS_ERROR]
    assert result.issues[0].file == "deep.py"
    assert result.status is ScanStatus.FAILED


def test_any_exception_in_the_detector_is_an_analysis_error_issue(monkeypatch):
    def broken(tree, *, file, policy):
        raise RuntimeError("boom")

    monkeypatch.setattr(command_injection, "detect", broken)

    result = STRICT.scan_source(VULNERABLE)

    assert codes(result) == [ANALYSIS_ERROR]
    assert result.issues[0].message == "boom"


def test_an_exception_with_no_message_still_gives_a_valid_issue(monkeypatch):
    def broken(tree, *, file, policy):
        raise RuntimeError()

    monkeypatch.setattr(command_injection, "detect", broken)

    assert STRICT.scan_source(VULNERABLE).issues[0].message == "RuntimeError"


def test_a_failure_in_parsing_other_than_syntax_is_an_analysis_error(monkeypatch):
    def broken(text):
        raise MemoryError()

    monkeypatch.setattr(engine_module.ast, "parse", broken)

    assert codes(STRICT.scan_source(VULNERABLE)) == [ANALYSIS_ERROR]


def test_python_warnings_from_scanned_code_are_not_emitted():
    with warnings.catch_warnings():
        warnings.simplefilter("error")

        result = STRICT.scan_source("x = '\\d'\n")

    assert result.status is ScanStatus.COMPLETE


# -- invalid arguments raise ---------------------------------------


@pytest.mark.parametrize("source", [None, 1, ["x"], bytearray(b"x = 1")])
def test_a_wrong_source_type_raises(source):
    with pytest.raises(ValueError, match="source"):
        STRICT.scan_source(source)


@pytest.mark.parametrize("source", ["", b""])
def test_an_empty_source_raises(source):
    with pytest.raises(ValueError, match="source must not be empty"):
        STRICT.scan_source(source)


def test_an_empty_source_raises_even_with_a_file_name():
    with pytest.raises(ValueError, match="source must not be empty"):
        STRICT.scan_source("", file="a.py")


@pytest.mark.parametrize("source", [" ", "\n", "# only a comment\n", b"\n"])
def test_a_blank_or_comment_only_source_is_valid(source):
    result = STRICT.scan_source(source)

    assert result.status is ScanStatus.COMPLETE
    assert result.metadata.files_scanned == 1


@pytest.mark.parametrize("file", ["", 1, b"a.py", ["a.py"]])
def test_a_wrong_file_raises(file):
    with pytest.raises(ValueError, match="file"):
        STRICT.scan_source(VULNERABLE, file=file)


# -- determinism and safety ----------------------------------------


def test_results_are_deterministic_and_round_trip():
    first = STRICT.scan_source(VULNERABLE, file="a.py").to_json()
    second = STRICT.scan_source(VULNERABLE, file="a.py").to_json()

    assert first == second
    assert ScanResult.from_json(first).to_json() == first


def test_created_at_is_not_set():
    assert STRICT.scan_source(VULNERABLE).metadata.created_at is None


def test_scanned_code_is_never_executed(tmp_path):
    marker = tmp_path / "marker.txt"
    source = f"open({str(marker)!r}, 'w').write('ran')\nimport os\nos.system(input())\n"

    result = STRICT.scan_source(source)

    assert len(result.findings) == 1
    assert not marker.exists()


# -- version --------------------------------------------------------


def test_the_tool_version_is_the_installed_version(monkeypatch):
    monkeypatch.setattr(engine_module, "installed_version", lambda: "9.9.9")

    result = ScanEngine().scan_source("x = 1\n")

    assert result.metadata.tool_version == "9.9.9"


def test_the_tool_version_is_none_when_not_installed(monkeypatch):
    monkeypatch.setattr(engine_module, "installed_version", lambda: None)

    assert ScanEngine().scan_source("x = 1\n").metadata.tool_version is None


def test_installed_version_falls_back_to_none(monkeypatch):
    def missing(name):
        raise engine_module.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(engine_module.metadata, "version", missing)

    assert installed_version() is None


def test_installed_version_returns_the_distribution_version(monkeypatch):
    monkeypatch.setattr(engine_module.metadata, "version", lambda name: "1.2.3")

    assert installed_version() == "1.2.3"


# -- link detection (platform independent) -------------------------

SYMLINK = 0o120777
DIRECTORY = 0o040755
REGULAR = 0o100644


def test_a_symlink_mode_is_a_link():
    assert is_link_like(SimpleNamespace(st_mode=SYMLINK))


def test_a_windows_junction_is_a_link():
    info = SimpleNamespace(
        st_mode=DIRECTORY,
        st_reparse_tag=engine_module.IO_REPARSE_TAG_MOUNT_POINT,
    )

    assert is_link_like(info)


def test_other_reparse_points_are_not_links():
    cloud_placeholder = 0x9000001A
    info = SimpleNamespace(st_mode=REGULAR, st_reparse_tag=cloud_placeholder)

    assert not is_link_like(info)


def test_plain_files_and_directories_are_not_links():
    assert not is_link_like(SimpleNamespace(st_mode=REGULAR))
    assert not is_link_like(SimpleNamespace(st_mode=DIRECTORY, st_reparse_tag=0))


def test_the_junction_tag_is_the_documented_windows_value():
    assert engine_module.IO_REPARSE_TAG_MOUNT_POINT == 0xA0000003
