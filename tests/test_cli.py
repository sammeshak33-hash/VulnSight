"""The ``vulnsight scan`` command line."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vulnsight import cli
from vulnsight.cli import build_parser, exit_code, format_text, main
from vulnsight.engine import ScanEngine
from vulnsight.scan_result import ScanResult

VULNERABLE = "import os\nos.system(input())\n"
PARAMETER_CODE = "import os\ndef run(cmd):\n    os.system(cmd)\n"
ROOT = Path(__file__).resolve().parent.parent


def write(path, text=VULNERABLE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")

    return path


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()

    return code, captured.out, captured.err


# -- exit codes -----------------------------------------------------


def test_exit_0_for_a_complete_scan_with_no_findings(tmp_path, capsys):
    write(tmp_path / "ok.py", "x = 1\n")

    code, out, err = run(capsys, "scan", str(tmp_path))

    assert code == 0
    assert "No findings." in out
    assert err == ""


def test_exit_1_for_a_complete_scan_with_findings(tmp_path, capsys):
    write(tmp_path / "bad.py")

    assert run(capsys, "scan", str(tmp_path))[0] == 1


def test_exit_3_for_a_partial_scan_even_with_findings(tmp_path, capsys):
    write(tmp_path / "a.py")
    write(tmp_path / "broken.py", "def (:\n")

    code, out, _ = run(capsys, "scan", str(tmp_path))

    assert code == 3
    assert "Status: partial" in out


def test_exit_4_for_a_failed_scan(tmp_path, capsys):
    code, out, _ = run(capsys, "scan", str(tmp_path / "missing"))

    assert code == 4
    assert "target-not-found" in out
    assert "Status: failed" in out


def test_exit_4_when_every_file_failed(tmp_path, capsys):
    write(tmp_path / "broken.py", "def (:\n")

    assert run(capsys, "scan", str(tmp_path))[0] == 4


def test_warnings_do_not_change_the_exit_code(tmp_path, capsys):
    code, out, _ = run(capsys, "scan", str(tmp_path))

    assert code == 0
    assert "no-python-files" in out
    assert "1 warning(s)" in out


def test_exit_code_function_covers_every_status(tmp_path):
    clean = ScanEngine().scan_source("x = 1\n")
    found = ScanEngine().scan_source(VULNERABLE)
    failed = ScanEngine().scan_source("def (:\n")

    assert exit_code(clean) == 0
    assert exit_code(found) == 1
    assert exit_code(failed) == 4

    write(tmp_path / "a.py")
    write(tmp_path / "b.py", "def (:\n")

    assert exit_code(ScanEngine().scan_path(tmp_path)) == 3


# -- usage errors ---------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["scan"],
        ["scan", "a", "b"],
        ["scan", "a", "--format", "xml"],
        ["scan", "a", "--parameter-mode", "loose"],
        ["scan", "a", "--no-such-option"],
        ["unknown"],
        ["scan", "a", "--output"],
    ],
)
def test_usage_errors_exit_2_with_a_message_on_stderr(capsys, argv):
    code, out, err = run(capsys, *argv)

    assert code == 2
    assert out == ""
    assert "usage:" in err


def test_an_empty_path_is_a_usage_error(capsys):
    code, out, err = run(capsys, "scan", "")

    assert code == 2
    assert out == ""
    assert "PATH" in err


def test_an_empty_output_path_is_a_usage_error(tmp_path, capsys):
    code, out, err = run(capsys, "scan", str(tmp_path), "--output", "")

    assert code == 2
    assert "--output" in err


def test_version_prints_and_exits_0(capsys, monkeypatch):
    monkeypatch.setattr(cli, "installed_version", lambda: "9.8.7")

    code, out, _ = run(capsys, "--version")

    assert code == 0
    assert out == "vulnsight 9.8.7\n"


def test_version_is_unknown_when_not_installed(capsys, monkeypatch):
    monkeypatch.setattr(cli, "installed_version", lambda: None)

    assert run(capsys, "--version")[1] == "vulnsight unknown\n"


def test_help_exits_0(capsys):
    code, out, _ = run(capsys, "scan", "--help")

    assert code == 0
    assert "--parameter-mode" in out


# -- text output ----------------------------------------------------


def test_text_report_layout_is_exact(tmp_path, capsys):
    write(tmp_path / "pkg" / "app.py")
    write(tmp_path / "bad.py", "def (:\n")
    target = str(tmp_path)

    code, out, _ = run(capsys, "scan", target)

    assert out == (
        "VulnSight scan\n"
        f"Target: {target.replace(chr(92), '/')}\n"
        "Parameter mode: strict\n"
        "\n"
        "pkg/app.py:2:1: PY-CMD-001 CWE-78 [medium, raw] os.system\n"
        "    Potential command injection: tainted data reaches os.system\n"
        "    Evidence: input() (line 2)\n"
        "\n"
        "Issues:\n"
        "  error    syntax-error  bad.py:1  invalid syntax\n"
        "\n"
        "Summary: 1 finding(s), 1 file(s) scanned, 1 error(s), 0 warning(s). "
        "Status: partial\n"
    )
    assert code == 3


def test_text_columns_are_one_based_and_json_columns_are_zero_based(tmp_path, capsys):
    write(tmp_path / "a.py", "import os\nif True:\n    os.system(input())\n")

    text = run(capsys, "scan", str(tmp_path))[1]
    data = json.loads(run(capsys, "scan", str(tmp_path), "--format", "json")[1])

    assert "a.py:3:5:" in text
    assert data["findings"][0]["location"]["column"] == 4


def test_a_finding_without_a_file_is_shown_as_memory():
    result = ScanEngine().scan_source(VULNERABLE)
    text = format_text(result)

    assert "<memory>:2:1: PY-CMD-001" in text
    assert "Target: <memory>" in text


def test_issues_without_a_file_show_no_location():
    text = format_text(ScanEngine().scan_source("x = '\xff'.encode()\ndef (:\n"))

    assert "  error    syntax-error  invalid syntax" in text


def test_text_output_ends_with_one_newline(tmp_path, capsys):
    write(tmp_path / "a.py")

    out = run(capsys, "scan", str(tmp_path))[1]

    assert out.endswith("\n")
    assert not out.endswith("\n\n")


def test_text_shows_the_recall_mode(tmp_path, capsys):
    write(tmp_path / "a.py", PARAMETER_CODE)

    out = run(capsys, "scan", str(tmp_path), "--parameter-mode", "recall")[1]

    assert "Parameter mode: recall" in out
    assert "[low, raw]" in out
    assert "param:run.cmd (line 2)" in out


# -- json output ----------------------------------------------------


def test_json_output_is_the_scan_result_and_round_trips(tmp_path, capsys):
    write(tmp_path / "a.py")
    write(tmp_path / "pkg" / "b.py")

    code, out, err = run(capsys, "scan", str(tmp_path), "--format", "json")
    result = ScanResult.from_json(out)

    assert code == 1
    assert err == ""
    assert result.to_json() + "\n" == out
    assert json.loads(out)["schema_version"] == "2.1"
    assert out.endswith("}\n")
    assert not out.endswith("\n\n")
    assert len(result.findings) == 2


def test_json_output_is_deterministic(tmp_path, capsys):
    write(tmp_path / "a.py")
    write(tmp_path / "b.py")

    first = run(capsys, "scan", str(tmp_path), "--format", "json")[1]
    second = run(capsys, "scan", str(tmp_path), "--format", "json")[1]

    assert first == second


def test_json_finding_ids_are_globally_unique(tmp_path, capsys):
    for name in ("a.py", "b.py", "c/d.py", "c/e.py"):
        write(tmp_path / name)

    out = run(capsys, "scan", str(tmp_path), "--format", "json")[1]
    ids = [finding["finding_id"] for finding in json.loads(out)["findings"]]

    assert len(ids) == 4
    assert len(set(ids)) == 4


def test_json_contains_no_timestamp(tmp_path, capsys):
    write(tmp_path / "a.py")

    out = run(capsys, "scan", str(tmp_path), "--format", "json")[1]

    assert json.loads(out)["metadata"]["created_at"] is None


def test_json_records_the_parameter_mode(tmp_path, capsys):
    write(tmp_path / "a.py", PARAMETER_CODE)

    strict = json.loads(run(capsys, "scan", str(tmp_path), "--format", "json")[1])
    recall = json.loads(
        run(
            capsys,
            "scan",
            str(tmp_path),
            "--format",
            "json",
            "--parameter-mode",
            "recall",
        )[1]
    )

    assert strict["metadata"]["settings"] == {"parameter_mode": "strict"}
    assert recall["metadata"]["settings"] == {"parameter_mode": "recall"}
    assert strict["findings"] == []
    assert recall["findings"][0]["confidence"] == "low"
    assert recall["findings"][0]["evidence"][0]["origin"]["kind"] == "parameter"


def test_json_for_a_failed_scan_is_still_valid(tmp_path, capsys):
    code, out, _ = run(capsys, "scan", str(tmp_path / "missing"), "--format", "json")
    result = ScanResult.from_json(out)

    assert code == 4
    assert result.status.value == "failed"
    assert result.issues[0].code == "target-not-found"


def test_strict_is_the_default_mode(tmp_path, capsys):
    write(tmp_path / "a.py", PARAMETER_CODE)

    assert run(capsys, "scan", str(tmp_path))[0] == 0


# -- output file ----------------------------------------------------


def test_output_writes_utf8_lf_without_bom_and_keeps_stdout_empty(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "out" / "report.json"
    report.parent.mkdir()

    code, out, err = run(
        capsys,
        "scan",
        str(tmp_path / "src"),
        "--format",
        "json",
        "--output",
        str(report),
    )
    data = report.read_bytes()

    assert code == 1
    assert out == ""
    assert err == f"Report written to {report}\n"
    assert not data.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in data
    assert data.endswith(b"}\n")
    assert ScanResult.from_json(data.decode("utf-8")).findings


def test_output_text_report_matches_stdout(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "report.txt"

    stdout_text = run(capsys, "scan", str(tmp_path / "src"))[1]
    run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert report.read_bytes().decode("utf-8") == stdout_text


def test_output_replaces_an_existing_file_completely(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "report.txt"
    report.write_text("old content " * 1000)

    run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert "old content" not in report.read_text()


def test_output_leaves_no_temporary_file_behind(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "out" / "report.txt"
    report.parent.mkdir()

    run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert os.listdir(report.parent) == ["report.txt"]


def test_output_in_a_missing_directory_fails_without_creating_it(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "missing" / "report.txt"

    code, out, err = run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert code == 4
    assert out == ""
    assert "cannot write report" in err
    assert "Report written" not in err
    assert not report.parent.exists()


def test_output_path_that_is_a_directory_fails_and_keeps_it(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    target = tmp_path / "out"
    target.mkdir()

    code, out, err = run(capsys, "scan", str(tmp_path / "src"), "-o", str(target))

    assert code == 4
    assert out == ""
    assert "cannot write report" in err
    assert target.is_dir()
    assert os.listdir(target) == []
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_output_failure_to_create_the_file_is_reported(tmp_path, capsys, monkeypatch):
    write(tmp_path / "src" / "a.py")

    def refuse(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(cli.os, "open", refuse)

    code, out, err = run(
        capsys, "scan", str(tmp_path / "src"), "-o", str(tmp_path / "r.txt")
    )

    assert code == 4
    assert out == ""
    assert "Permission denied" in err
    assert "Report written" not in err


def test_a_write_that_fails_partway_keeps_the_old_file(tmp_path, capsys, monkeypatch):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "report.txt"
    report.write_text("previous report")
    real_fdopen = os.fdopen

    class Failing:
        def __init__(self, handle):
            self._handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._handle.close()

            return False

        def write(self, data):
            self._handle.write(data[: len(data) // 2])
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(
        cli.os, "fdopen", lambda *args, **kwargs: Failing(real_fdopen(*args, **kwargs))
    )

    code, out, err = run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert code == 4
    assert out == ""
    assert "No space left on device" in err
    assert "Report written" not in err
    assert report.read_text() == "previous report"
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


@pytest.mark.parametrize("existing", [False, True])
def test_an_unexpected_error_while_writing_is_an_internal_error(
    tmp_path, capsys, monkeypatch, existing
):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "report.txt"

    if existing:
        report.write_text("previous report")

    def explode(source, destination):
        raise RuntimeError("replace bug")

    monkeypatch.setattr(cli.os, "replace", explode)

    code, out, err = run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert code == 4
    assert out == ""
    assert "internal error (RuntimeError): replace bug" in err
    assert "Traceback" not in err
    assert "Report written" not in err
    assert "cannot write report" not in err
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []

    if existing:
        assert report.read_text() == "previous report"
    else:
        assert not report.exists()


def test_an_unexpected_error_writing_to_stdout_is_an_internal_error(
    tmp_path, capsys, monkeypatch
):
    write(tmp_path / "a.py")

    class Broken:
        def write(self, text):
            raise RuntimeError("stdout bug")

        def flush(self):
            pass

    monkeypatch.setattr(cli.sys, "stdout", Broken())

    assert main(["scan", str(tmp_path)]) == 4

    err = capsys.readouterr().err

    assert "internal error (RuntimeError): stdout bug" in err
    assert "Traceback" not in err


def test_a_failure_replacing_the_file_cleans_up_and_fails(
    tmp_path, capsys, monkeypatch
):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "report.txt"

    def refuse(source, destination):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(cli.os, "replace", refuse)

    code, _, err = run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert code == 4
    assert "Permission denied" in err
    assert not report.exists()
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_a_failed_scan_still_writes_its_report(tmp_path, capsys):
    report = tmp_path / "report.json"

    code, _, err = run(
        capsys,
        "scan",
        str(tmp_path / "missing"),
        "--format",
        "json",
        "-o",
        str(report),
    )

    assert code == 4
    assert err == f"Report written to {report}\n"
    assert ScanResult.from_json(report.read_text()).status.value == "failed"


def test_output_equal_to_the_scanned_file_is_refused_before_scanning(tmp_path, capsys):
    path = write(tmp_path / "app.py")
    before = path.read_text()

    code, out, err = run(capsys, "scan", str(path), "--output", str(path))

    assert code == 2
    assert out == ""
    assert "--output" in err
    assert path.read_text() == before


def test_output_through_a_link_to_the_scanned_file_is_refused(tmp_path, capsys):
    path = write(tmp_path / "app.py")
    alias = tmp_path / "alias.txt"

    try:
        os.link(path, alias)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("hard links are not available here")

    code, _, _ = run(capsys, "scan", str(path), "-o", str(alias))

    assert code == 2
    assert path.read_text() == VULNERABLE


def test_output_replaces_a_symlink_at_the_output_path_instead_of_writing_through(
    tmp_path, capsys
):
    write(tmp_path / "src" / "a.py")
    kept = write(tmp_path / "kept.txt", "keep me")
    report = tmp_path / "report.txt"

    try:
        os.symlink(kept, report)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")

    run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert kept.read_text() == "keep me"
    assert not report.is_symlink()
    assert "VulnSight scan" in report.read_text()


def test_output_inside_the_scanned_directory_is_allowed(tmp_path, capsys):
    write(tmp_path / "a.py")
    report = tmp_path / "report.json"

    code, _, err = run(
        capsys, "scan", str(tmp_path), "--format", "json", "-o", str(report)
    )

    assert code == 1
    assert report.exists()
    assert "Report written" in err


# -- robustness -----------------------------------------------------


def test_an_unexpected_exception_is_an_internal_error_without_traceback(
    tmp_path, capsys, monkeypatch
):
    def explode(self, path):
        raise RuntimeError("engine bug")

    monkeypatch.setattr(ScanEngine, "scan_path", explode)

    code, out, err = run(capsys, "scan", str(tmp_path))

    assert code == 4
    assert out == ""
    assert "internal error (RuntimeError): engine bug" in err
    assert "Traceback" not in err


def test_a_closed_stdout_is_reported(tmp_path, capsys, monkeypatch):
    write(tmp_path / "a.py")

    class Closed:
        def write(self, text):
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self):
            pass

    monkeypatch.setattr(cli.sys, "stdout", Closed())

    assert main(["scan", str(tmp_path)]) == 4
    assert "Broken pipe" in capsys.readouterr().err


def test_scanned_code_is_never_executed_by_the_cli(tmp_path, capsys):
    marker = tmp_path / "marker.txt"
    write(
        tmp_path / "src" / "evil.py",
        f"open({str(marker)!r}, 'w').write('ran')\n" + VULNERABLE,
    )

    assert run(capsys, "scan", str(tmp_path / "src"))[0] == 1
    assert not marker.exists()


def test_the_parser_defaults():
    arguments = build_parser().parse_args(["scan", "x"])

    assert arguments.parameter_mode == "strict"
    assert arguments.format == "text"
    assert arguments.output is None


# -- real process ---------------------------------------------------


def test_python_dash_m_vulnsight_scan_works_in_a_subprocess(tmp_path):
    write(tmp_path / "src" / "a.py")
    environment = dict(os.environ, PYTHONPATH=str(ROOT))

    outcome = subprocess.run(
        [
            sys.executable,
            "-m",
            "vulnsight",
            "scan",
            str(tmp_path / "src"),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
        cwd=tmp_path,
        check=False,
    )

    assert outcome.returncode == 1
    assert outcome.stderr == ""
    assert ScanResult.from_json(outcome.stdout).findings


def test_python_dash_m_vulnsight_usage_error_exit_code(tmp_path):
    environment = dict(os.environ, PYTHONPATH=str(ROOT))

    outcome = subprocess.run(
        [sys.executable, "-m", "vulnsight"],
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
        check=False,
    )

    assert outcome.returncode == 2
    assert "usage:" in outcome.stderr
