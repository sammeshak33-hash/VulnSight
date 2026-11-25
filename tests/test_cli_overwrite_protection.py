"""A report must never overwrite a file that is being scanned."""

import os
from types import SimpleNamespace

import pytest

from vulnsight import cli
from vulnsight.cli import main
from vulnsight.engine import ScanEngine, discover_files

SOURCE = "import os\nos.system(input())\n"


def write(path, text=SOURCE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")

    return path


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()

    return code, captured.out, captured.err


def symlink(link, target):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")


def hardlink(link, target):
    try:
        os.link(target, link)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("hard links are not available here")


def temporary_files(root):
    return [
        name for _, _, names in os.walk(root) for name in names if name.endswith(".tmp")
    ]


def assert_rejected(capsys, tmp_path, scanned, output, *extra):
    """Run the scan and check it was refused without touching anything."""

    originals = {
        path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
    }

    code, out, err = run(capsys, "scan", str(scanned), "-o", str(output), *extra)

    assert code == 2
    assert out == ""
    assert "--output would overwrite a file that is being scanned" in err
    assert "Report written" not in err
    assert "usage:" in err

    for path, content in originals.items():
        assert path.read_bytes() == content, f"{path} changed"

    assert temporary_files(tmp_path) == []


# -- direct paths ---------------------------------------------------


def test_a_report_targeting_a_scanned_py_file_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "src" / "a.py")

    assert_rejected(capsys, tmp_path, tmp_path / "src", source)


def test_a_report_targeting_a_nested_scanned_file_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "src" / "pkg" / "deep" / "b.py")
    write(tmp_path / "src" / "a.py")

    assert_rejected(capsys, tmp_path, tmp_path / "src", source)


def test_the_json_format_is_rejected_too(tmp_path, capsys):
    source = write(tmp_path / "src" / "a.py")

    assert_rejected(capsys, tmp_path, tmp_path / "src", source, "--format", "json")


@pytest.mark.parametrize(
    "spelling",
    ["dot", "parent", "double-separator"],
)
def test_other_spellings_of_a_scanned_path_are_rejected(
    tmp_path, capsys, monkeypatch, spelling
):
    write(tmp_path / "src" / "a.py")
    monkeypatch.chdir(tmp_path)
    output = {
        "dot": os.path.join("src", ".", "a.py"),
        "parent": os.path.join("src", "..", "src", "a.py"),
        "double-separator": "src" + os.sep + os.sep + "a.py",
    }[spelling]

    assert_rejected(capsys, tmp_path, "src", output)


def test_a_relative_report_path_is_rejected(tmp_path, capsys, monkeypatch):
    write(tmp_path / "src" / "a.py")
    monkeypatch.chdir(tmp_path / "src")

    assert_rejected(capsys, tmp_path, ".", "a.py")


def test_a_path_through_a_linked_parent_directory_is_rejected(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    symlink(tmp_path / "shortcut", tmp_path / "src")

    assert_rejected(capsys, tmp_path, tmp_path / "src", tmp_path / "shortcut" / "a.py")


def test_the_explicit_file_target_itself_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "app.py")

    assert_rejected(capsys, tmp_path, source, source)


def test_an_explicit_file_without_an_extension_is_protected(tmp_path, capsys):
    source = write(tmp_path / "script")

    assert_rejected(capsys, tmp_path, source, source)


def test_the_scanned_directory_itself_is_rejected(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")

    code, out, err = run(
        capsys, "scan", str(tmp_path / "src"), "-o", str(tmp_path / "src")
    )

    assert code == 2
    assert out == ""
    assert "would overwrite" in err


@pytest.mark.skipif(
    not os.path.exists(__file__.upper()),
    reason="needs a case-insensitive file system",
)
def test_a_different_letter_case_is_rejected_on_case_insensitive_systems(
    tmp_path, capsys
):
    source = write(tmp_path / "src" / "a.py")

    assert_rejected(capsys, tmp_path, tmp_path / "src", str(source).upper())


# -- symbolic link aliases -----------------------------------------


def test_a_symlink_to_a_scanned_file_outside_the_directory_is_rejected(
    tmp_path, capsys
):
    source = write(tmp_path / "src" / "a.py")
    alias = tmp_path / "report.txt"
    symlink(alias, source)

    assert_rejected(capsys, tmp_path, tmp_path / "src", alias)
    assert alias.is_symlink()


def test_a_symlink_to_a_scanned_file_inside_the_directory_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "src" / "a.py")
    alias = tmp_path / "src" / "report.txt"
    symlink(alias, source)

    assert_rejected(capsys, tmp_path, tmp_path / "src", alias)


def test_a_py_named_symlink_to_a_scanned_file_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "src" / "a.py")
    alias = tmp_path / "src" / "alias.py"
    symlink(alias, source)

    assert_rejected(capsys, tmp_path, tmp_path / "src", alias)


def test_a_symlink_to_the_explicit_target_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "app.py")
    alias = tmp_path / "report.txt"
    symlink(alias, source)

    assert_rejected(capsys, tmp_path, source, alias)


def test_a_chain_of_symlinks_to_a_scanned_file_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "src" / "a.py")
    symlink(tmp_path / "one", source)
    symlink(tmp_path / "two", tmp_path / "one")

    assert_rejected(capsys, tmp_path, tmp_path / "src", tmp_path / "two")


# -- hard link aliases ---------------------------------------------


def test_a_hard_link_to_a_scanned_file_outside_the_directory_is_rejected(
    tmp_path, capsys
):
    source = write(tmp_path / "src" / "a.py")
    alias = tmp_path / "report.txt"
    hardlink(alias, source)

    assert_rejected(capsys, tmp_path, tmp_path / "src", alias)


def test_a_hard_link_to_a_scanned_file_inside_the_directory_is_rejected(
    tmp_path, capsys
):
    source = write(tmp_path / "src" / "a.py")
    alias = tmp_path / "src" / "pkg" / "report.json"
    alias.parent.mkdir()
    hardlink(alias, source)

    assert_rejected(capsys, tmp_path, tmp_path / "src", alias, "--format", "json")


def test_a_hard_link_to_the_explicit_target_is_rejected(tmp_path, capsys):
    source = write(tmp_path / "app.py")
    alias = tmp_path / "report.txt"
    hardlink(alias, source)

    assert_rejected(capsys, tmp_path, source, alias)


# -- reports that are allowed --------------------------------------


def test_a_normal_report_inside_the_scanned_directory_is_allowed(tmp_path, capsys):
    source = write(tmp_path / "src" / "a.py")
    report = tmp_path / "src" / "report.json"

    code, out, err = run(
        capsys,
        "scan",
        str(tmp_path / "src"),
        "--format",
        "json",
        "-o",
        str(report),
    )

    assert code == 1
    assert out == ""
    assert err == f"Report written to {report}\n"
    assert report.exists()
    assert source.read_text() == SOURCE


def test_a_report_in_a_subdirectory_of_the_scan_is_allowed(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    reports = tmp_path / "src" / "reports"
    reports.mkdir()

    code, _, _ = run(
        capsys, "scan", str(tmp_path / "src"), "-o", str(reports / "r.txt")
    )

    assert code == 1
    assert (reports / "r.txt").exists()


def test_an_existing_non_source_file_may_be_replaced(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    old = write(tmp_path / "src" / "report.txt", "old report")

    code, _, _ = run(capsys, "scan", str(tmp_path / "src"), "-o", str(old))

    assert code == 1
    assert "VulnSight scan" in old.read_text()


def test_a_report_outside_the_scanned_directory_is_allowed(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")

    code, _, _ = run(
        capsys, "scan", str(tmp_path / "src"), "-o", str(tmp_path / "out.txt")
    )

    assert code == 1


def test_a_py_file_that_the_scan_does_not_read_may_be_replaced(tmp_path, capsys):
    # The same file selection as the engine: skipped directories are not read.
    write(tmp_path / "src" / "a.py")
    ignored = write(tmp_path / "src" / ".venv" / "lib.py", "old")

    code, _, _ = run(capsys, "scan", str(tmp_path / "src"), "-o", str(ignored))

    assert code == 1
    assert "VulnSight scan" in ignored.read_text()


def test_a_py_symlink_to_a_file_the_scan_does_not_read_is_allowed(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    elsewhere = write(tmp_path / "elsewhere" / "x.py", "keep")
    alias = tmp_path / "src" / "alias.py"
    symlink(alias, elsewhere)

    code, _, _ = run(capsys, "scan", str(tmp_path / "src"), "-o", str(alias))

    assert code == 1
    assert elsewhere.read_text() == "keep"
    assert not alias.is_symlink()


def test_a_hard_link_to_a_file_the_scan_does_not_read_is_allowed(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    elsewhere = write(tmp_path / "elsewhere" / "x.py", "keep")
    alias = tmp_path / "report.txt"
    hardlink(alias, elsewhere)

    code, _, _ = run(capsys, "scan", str(tmp_path / "src"), "-o", str(alias))

    assert code == 1
    assert elsewhere.read_text() == "keep"


def test_an_output_path_that_does_not_exist_yet_is_allowed(tmp_path, capsys):
    write(tmp_path / "src" / "a.py")
    report = tmp_path / "src" / "new-report.txt"

    code, _, _ = run(capsys, "scan", str(tmp_path / "src"), "-o", str(report))

    assert code == 1
    assert report.exists()


# -- the check follows the engine's rules --------------------------


def test_discover_files_matches_exactly_the_files_the_engine_scans(tmp_path):
    root = tmp_path / "src"

    for name in ("a.py", "pkg/b.py", "pkg/deep/c.py"):
        write(root / name)

    for name in (".venv/x.py", "node_modules/y.py", "pkg/__pycache__/z.py"):
        write(root / name)

    write(root / "notes.txt")
    write(root / "stub.pyi")
    symlink(root / "alias.py", root / "a.py")
    symlink(root / "linked", root / "pkg")

    scanned = {
        finding.location.file for finding in ScanEngine().scan_path(root).findings
    }
    discovered = {
        os.path.relpath(path, root).replace(os.sep, "/")
        for path in discover_files(root)
    }

    assert scanned == discovered == {"a.py", "pkg/b.py", "pkg/deep/c.py"}


def test_discover_files_for_explicit_targets(tmp_path):
    plain = write(tmp_path / "script")
    symlink(tmp_path / "link.py", plain)

    assert discover_files(plain) == (str(plain),)
    assert discover_files(tmp_path / "missing") == ()
    assert discover_files(tmp_path / "link.py") == ()


@pytest.mark.parametrize("path", ["", "a\x00b", None, 3])
def test_discover_files_rejects_invalid_arguments(path):
    with pytest.raises(ValueError):
        discover_files(path)


def test_discover_files_is_sorted_and_survives_unreadable_directories(
    tmp_path, monkeypatch
):
    write(tmp_path / "b.py")
    write(tmp_path / "a.py")
    write(tmp_path / "locked" / "x.py")
    real = os.scandir

    def fake(path="."):
        if str(path).endswith("locked"):
            raise PermissionError(13, "Permission denied")

        return real(path)

    monkeypatch.setattr(os, "scandir", fake)

    assert [os.path.basename(p) for p in discover_files(tmp_path)] == [
        "a.py",
        "b.py",
    ]


# -- file identity helper ------------------------------------------


def test_identical_is_true_only_for_the_same_file(tmp_path):
    first = write(tmp_path / "a.txt")
    other = write(tmp_path / "b.txt")

    assert cli._identical(first, first)
    assert not cli._identical(first, other)
    assert not cli._identical(first, tmp_path / "missing")
    assert not cli._identical(tmp_path / "missing", tmp_path / "missing")


def test_identical_falls_back_to_resolved_paths_without_file_identity(
    tmp_path, monkeypatch
):
    first = write(tmp_path / "a.txt")
    other = write(tmp_path / "b.txt")
    real = os.stat

    def no_identity(path, *args, **kwargs):
        info = real(path, *args, **kwargs)

        return SimpleNamespace(st_ino=0, st_dev=0, st_mode=info.st_mode)

    monkeypatch.setattr(cli.os, "stat", no_identity)

    assert cli._identical(first, tmp_path / "." / "a.txt")
    assert not cli._identical(first, other)


def test_an_unexpected_failure_in_the_check_is_an_internal_error(
    tmp_path, capsys, monkeypatch
):
    source = write(tmp_path / "src" / "a.py")

    def explode(output, path):
        raise RuntimeError("check bug")

    monkeypatch.setattr(cli, "_overwritten_source", explode)

    code, out, err = run(
        capsys, "scan", str(tmp_path / "src"), "-o", str(tmp_path / "r.txt")
    )

    assert code == 4
    assert out == ""
    assert "internal error (RuntimeError): check bug" in err
    assert source.read_text() == SOURCE
    assert not (tmp_path / "r.txt").exists()
