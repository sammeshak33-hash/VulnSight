"""ScanEngine.scan_path: files, directories, symlinks and traversal errors."""

import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnsight import engine as engine_module
from vulnsight.engine import (
    ANALYSIS_ERROR,
    ENCODING_ERROR,
    NO_PYTHON_FILES,
    READ_ERROR,
    SKIPPED_DIRECTORIES,
    SYMLINK_SKIPPED,
    SYNTAX_ERROR,
    TARGET_NOT_FOUND,
    TARGET_SYMLINK,
    TARGET_UNREADABLE,
    TARGET_UNSUPPORTED,
    WALK_ERROR,
    ScanEngine,
)
from vulnsight.scan_result import IssueLevel, ScanResult, ScanStatus
from vulnsight.scanner.policy import ParameterMode

VULNERABLE = "import os\nos.system(input())\n"
PARAMETER_CODE = "import os\ndef run(cmd):\n    os.system(cmd)\n"

ENGINE = ScanEngine()


def write(path, text=VULNERABLE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")

    return path


def codes(result):
    return [issue.code for issue in result.issues]


def issue_files(result):
    return [(issue.code, issue.file) for issue in result.issues]


def finding_files(result):
    return [finding.location.file for finding in result.findings]


def make_symlink(link, target, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")


# -- a single file --------------------------------------------------


def test_a_single_file_is_scanned_and_named_by_its_base_name(tmp_path):
    path = write(tmp_path / "sub" / "app.py")

    result = ENGINE.scan_path(path)

    assert result.status is ScanStatus.COMPLETE
    assert finding_files(result) == ["app.py"]
    assert result.metadata.files_scanned == 1


def test_an_explicit_file_is_scanned_whatever_its_extension(tmp_path):
    path = write(tmp_path / "script")

    assert len(ENGINE.scan_path(path).findings) == 1

    path = write(tmp_path / "notes.txt")

    assert len(ENGINE.scan_path(path).findings) == 1


def test_the_target_is_kept_as_given_with_forward_slashes(tmp_path):
    path = write(tmp_path / "app.py")

    result = ENGINE.scan_path(str(path))

    assert result.target == str(path).replace("\\", "/")


def test_a_relative_target_stays_relative(tmp_path, monkeypatch):
    write(tmp_path / "app.py")
    monkeypatch.chdir(tmp_path)

    assert ENGINE.scan_path("app.py").target == "app.py"
    assert ENGINE.scan_path("./app.py").target == "./app.py"


def test_a_backslash_target_is_normalized(tmp_path):
    result = ENGINE.scan_path("no\\such\\dir")

    assert result.target == "no/such/dir"
    assert codes(result) == [TARGET_NOT_FOUND]


def test_path_like_and_bytes_targets_are_accepted(tmp_path):
    path = write(tmp_path / "app.py")

    assert len(ENGINE.scan_path(Path(path)).findings) == 1

    if os.name == "posix":
        assert len(ENGINE.scan_path(os.fsencode(path)).findings) == 1


@pytest.mark.parametrize("path", ["", "a\x00b", None, 3, ["a"]])
def test_an_invalid_path_argument_raises(path):
    with pytest.raises(ValueError):
        ENGINE.scan_path(path)


def test_an_empty_file_on_disk_is_a_valid_scan_target(tmp_path):
    path = write(tmp_path / "empty.py", "")

    result = ENGINE.scan_path(path)

    assert result.status is ScanStatus.COMPLETE
    assert result.metadata.files_scanned == 1
    assert result.findings == ()


def test_an_empty_file_in_a_directory_counts_as_scanned(tmp_path):
    write(tmp_path / "__init__.py", "")

    result = ENGINE.scan_path(tmp_path)

    assert result.metadata.files_scanned == 1
    assert result.issues == ()


# -- directories ----------------------------------------------------


def test_a_directory_is_searched_recursively_for_py_files(tmp_path):
    write(tmp_path / "a.py")
    write(tmp_path / "pkg" / "b.py")
    write(tmp_path / "pkg" / "deep" / "c.py")
    write(tmp_path / "notes.txt")
    write(tmp_path / "script")
    write(tmp_path / "stub.pyi")
    write(tmp_path / "UPPER.PY")

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["a.py", "pkg/b.py", "pkg/deep/c.py"]
    assert result.metadata.files_scanned == 3
    assert result.status is ScanStatus.COMPLETE
    assert result.issues == ()


def test_paths_are_relative_to_the_directory_with_forward_slashes(tmp_path):
    write(tmp_path / "pkg" / "mod.py")

    result = ENGINE.scan_path(str(tmp_path) + os.sep)

    assert finding_files(result) == ["pkg/mod.py"]
    assert all("\\" not in file for file in finding_files(result))


@pytest.mark.parametrize("name", sorted(SKIPPED_DIRECTORIES))
def test_skipped_directories_are_not_entered_and_are_silent(tmp_path, name):
    write(tmp_path / "keep.py")
    write(tmp_path / name / "inner.py")
    write(tmp_path / "pkg" / name / "inner.py")

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["keep.py"]
    assert result.issues == ()


def test_a_directory_named_like_a_skipped_one_but_longer_is_scanned(tmp_path):
    write(tmp_path / "venv_tools" / "x.py")

    assert finding_files(ENGINE.scan_path(tmp_path)) == ["venv_tools/x.py"]


def test_an_empty_directory_is_complete_with_a_warning(tmp_path):
    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.COMPLETE
    assert result.metadata.files_scanned == 0
    assert codes(result) == [NO_PYTHON_FILES]
    assert result.issues[0].level is IssueLevel.WARNING


def test_a_directory_with_only_other_files_gets_the_warning(tmp_path):
    write(tmp_path / "readme.txt")

    assert codes(ENGINE.scan_path(tmp_path)) == [NO_PYTHON_FILES]


def test_the_result_does_not_depend_on_creation_order_or_working_directory(
    tmp_path, monkeypatch
):
    names = ["z.py", "a.py", "pkg/m.py", "pkg/b.py", "bad.py"]
    first, second = tmp_path / "one", tmp_path / "two"

    for name in names:
        write(first / name, "def (:\n" if name == "bad.py" else VULNERABLE)

    for name in reversed(names):
        write(second / name, "def (:\n" if name == "bad.py" else VULNERABLE)

    a = ENGINE.scan_path(first)
    monkeypatch.chdir(tmp_path / "two")
    b = ENGINE.scan_path(second)

    assert a.to_json().replace(str(first).replace("\\", "/"), "T") == (
        b.to_json().replace(str(second).replace("\\", "/"), "T")
    )


def test_finding_ids_are_unique_across_files(tmp_path):
    for name in ("a.py", "b.py", "pkg/c.py", "pkg/d.py"):
        write(tmp_path / name)

    result = ENGINE.scan_path(tmp_path)
    ids = [finding.finding_id for finding in result.findings]

    assert len(ids) == 4
    assert len(set(ids)) == 4
    assert sorted(finding.occurrence for finding in result.findings) == [0, 1, 2, 3]


def test_occurrence_numbers_follow_path_order_not_discovery_order(tmp_path):
    for name in ("b.py", "a.py", "c.py"):
        write(tmp_path / name)

    result = ENGINE.scan_path(tmp_path)

    assert [(f.location.file, f.occurrence) for f in result.findings] == [
        ("a.py", 0),
        ("b.py", 1),
        ("c.py", 2),
    ]


def test_a_directory_result_round_trips_through_json(tmp_path):
    write(tmp_path / "a.py")
    write(tmp_path / "bad.py", "def (:\n")

    text = ENGINE.scan_path(tmp_path).to_json()

    assert ScanResult.from_json(text).to_json() == text


def test_a_deep_tree_is_walked(tmp_path):
    path = tmp_path

    for _ in range(25):
        path = path / "d"

    write(path / "deep.py")

    assert len(ENGINE.scan_path(tmp_path).findings) == 1


def test_scanned_files_are_never_executed(tmp_path):
    marker = tmp_path / "marker.txt"
    code = f"open({str(marker)!r}, 'w').write('ran')\n" + VULNERABLE

    write(tmp_path / "pkg" / "evil.py", code)
    write(tmp_path / "conftest.py", code)

    result = ENGINE.scan_path(tmp_path)

    assert len(result.findings) == 2
    assert not marker.exists()


def test_recall_mode_applies_to_directories(tmp_path):
    write(tmp_path / "a.py", PARAMETER_CODE)

    strict = ScanEngine().scan_path(tmp_path)
    recall = ScanEngine(parameter_mode=ParameterMode.RECALL).scan_path(tmp_path)

    assert strict.findings == ()
    assert len(recall.findings) == 1
    assert recall.metadata.settings_dict() == {"parameter_mode": "recall"}


# -- errors inside files -------------------------------------------


def test_one_bad_file_makes_the_scan_partial(tmp_path):
    write(tmp_path / "good.py")
    write(tmp_path / "bad.py", "def (:\n")

    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.PARTIAL
    assert result.metadata.files_scanned == 1
    assert issue_files(result) == [(SYNTAX_ERROR, "bad.py")]
    assert finding_files(result) == ["good.py"]


def test_files_scanned_counts_only_analysed_files(tmp_path):
    write(tmp_path / "ok.py", "x = 1\n")
    write(tmp_path / "ok2.py")
    write(tmp_path / "syntax.py", "def (:\n")
    (tmp_path / "latin.py").write_bytes(b"x = '\xff'\n")
    (tmp_path / "nul.py").write_bytes(b"x = 1\x00\n")

    result = ENGINE.scan_path(tmp_path)

    assert result.metadata.files_scanned == 2
    assert sorted(codes(result)) == sorted([ENCODING_ERROR, SYNTAX_ERROR, SYNTAX_ERROR])
    assert result.status is ScanStatus.PARTIAL


def test_a_directory_where_nothing_could_be_analysed_has_failed(tmp_path):
    write(tmp_path / "bad.py", "def (:\n")
    write(tmp_path / "bad2.py", "class\n")

    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.FAILED
    assert result.metadata.files_scanned == 0
    assert NO_PYTHON_FILES not in codes(result)


def test_an_explicit_file_with_a_syntax_error_has_failed(tmp_path):
    path = write(tmp_path / "bad.py", "def (:\n")

    result = ENGINE.scan_path(path)

    assert result.status is ScanStatus.FAILED
    assert issue_files(result) == [(SYNTAX_ERROR, "bad.py")]


def test_an_analysis_error_in_one_file_does_not_stop_the_others(tmp_path):
    chain = "+".join(["a"] * 900)
    write(tmp_path / "deep.py", f"import os\na = input()\nos.system({chain})\n")
    write(tmp_path / "ok.py")

    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.PARTIAL
    assert issue_files(result) == [(ANALYSIS_ERROR, "deep.py")]
    assert finding_files(result) == ["ok.py"]


def test_an_unreadable_file_is_a_read_error_and_the_scan_continues(
    tmp_path, monkeypatch
):
    write(tmp_path / "locked.py")
    write(tmp_path / "ok.py")
    real_open = open

    def fake_open(file, *args, **kwargs):
        if str(file).endswith("locked.py"):
            raise PermissionError(13, "Permission denied", str(file))

        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(engine_module, "open", fake_open, raising=False)

    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.PARTIAL
    assert issue_files(result) == [(READ_ERROR, "locked.py")]
    assert result.issues[0].message == "Permission denied"
    assert str(tmp_path) not in result.issues[0].message
    assert finding_files(result) == ["ok.py"]


def test_an_unreadable_explicit_file_has_failed(tmp_path, monkeypatch):
    path = write(tmp_path / "locked.py")

    def fake_open(file, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(file))

    monkeypatch.setattr(engine_module, "open", fake_open, raising=False)

    result = ENGINE.scan_path(path)

    assert result.status is ScanStatus.FAILED
    assert issue_files(result) == [(READ_ERROR, "locked.py")]


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX file names")
def test_an_undecodable_file_name_is_escaped_not_fatal(tmp_path):
    raw = os.fsencode(str(tmp_path)) + b"/bad\xff.py"

    with open(raw, "w", encoding="utf-8") as handle:
        handle.write(VULNERABLE)

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["bad\ufffd.py"]
    assert ScanResult.from_json(result.to_json()) == result


# -- targets that cannot be scanned --------------------------------


def test_a_missing_target_has_failed(tmp_path):
    result = ENGINE.scan_path(tmp_path / "nope")

    assert result.status is ScanStatus.FAILED
    assert codes(result) == [TARGET_NOT_FOUND]
    assert result.metadata.files_scanned == 0
    assert result.findings == ()


def test_a_path_through_a_file_is_not_found(tmp_path):
    path = write(tmp_path / "app.py")

    assert codes(ENGINE.scan_path(path / "child")) == [TARGET_NOT_FOUND]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_named_pipe_target_is_unsupported_and_never_opened(tmp_path):
    fifo = tmp_path / "pipe.py"
    os.mkfifo(fifo)

    result = ENGINE.scan_path(fifo)

    assert codes(result) == [TARGET_UNSUPPORTED]
    assert result.status is ScanStatus.FAILED


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_named_pipe_inside_a_directory_is_ignored(tmp_path):
    os.mkfifo(tmp_path / "pipe.py")
    write(tmp_path / "ok.py")

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["ok.py"]
    assert result.issues == ()


def test_a_target_that_cannot_be_inspected_is_unreadable(tmp_path, monkeypatch):
    real = os.lstat

    def fake(path, *args, **kwargs):
        if str(path).endswith("locked"):
            raise PermissionError(13, "Permission denied", str(path))

        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fake)

    result = ENGINE.scan_path(tmp_path / "locked")

    assert codes(result) == [TARGET_UNREADABLE]
    assert result.status is ScanStatus.FAILED


# -- symbolic links ------------------------------------------------


def test_a_symlinked_py_file_is_skipped_with_a_warning(tmp_path):
    write(tmp_path / "real.py")
    make_symlink(tmp_path / "alias.py", "real.py")

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["real.py"]
    assert issue_files(result) == [(SYMLINK_SKIPPED, "alias.py")]
    assert result.issues[0].level is IssueLevel.WARNING
    assert result.status is ScanStatus.COMPLETE


def test_a_symlinked_directory_is_not_entered_and_is_reported(tmp_path):
    write(tmp_path / "real" / "m.py")
    make_symlink(tmp_path / "alias", "real", directory=True)

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["real/m.py"]
    assert issue_files(result) == [(SYMLINK_SKIPPED, "alias")]


def test_a_directory_symlink_loop_is_harmless(tmp_path):
    write(tmp_path / "pkg" / "m.py")
    make_symlink(tmp_path / "pkg" / "loop", "..", directory=True)

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["pkg/m.py"]
    assert issue_files(result) == [(SYMLINK_SKIPPED, "pkg/loop")]


def test_a_broken_py_symlink_is_reported(tmp_path):
    make_symlink(tmp_path / "ghost.py", "missing.py")
    write(tmp_path / "ok.py")

    result = ENGINE.scan_path(tmp_path)

    assert issue_files(result) == [(SYMLINK_SKIPPED, "ghost.py")]
    assert finding_files(result) == ["ok.py"]


def test_other_symlinks_to_files_are_ignored_silently(tmp_path):
    write(tmp_path / "data.txt", "x")
    make_symlink(tmp_path / "data-link", "data.txt")
    make_symlink(tmp_path / "dangling", "nowhere")
    write(tmp_path / "ok.py")

    result = ENGINE.scan_path(tmp_path)

    assert result.issues == ()


def test_an_explicit_symlink_to_a_file_is_not_followed(tmp_path):
    write(tmp_path / "real.py")
    make_symlink(tmp_path / "alias.py", "real.py")

    result = ENGINE.scan_path(tmp_path / "alias.py")

    assert result.status is ScanStatus.FAILED
    assert codes(result) == [TARGET_SYMLINK]
    assert result.issues[0].level is IssueLevel.ERROR
    assert result.findings == ()
    assert result.metadata.files_scanned == 0
    assert result.target == str(tmp_path / "alias.py").replace("\\", "/")


def test_an_explicit_symlink_to_a_directory_is_not_followed(tmp_path):
    write(tmp_path / "real" / "m.py")
    make_symlink(tmp_path / "alias", "real", directory=True)

    result = ENGINE.scan_path(tmp_path / "alias")

    assert codes(result) == [TARGET_SYMLINK]
    assert result.status is ScanStatus.FAILED


def test_a_symlink_typed_with_a_trailing_separator_is_still_detected(tmp_path):
    write(tmp_path / "real" / "m.py")
    make_symlink(tmp_path / "alias", "real", directory=True)

    for suffix in ("/", os.sep):
        result = ENGINE.scan_path(str(tmp_path / "alias") + suffix)

        assert codes(result) == [TARGET_SYMLINK]
        assert result.findings == ()


def test_an_explicit_broken_symlink_is_reported_as_a_symlink(tmp_path):
    make_symlink(tmp_path / "ghost.py", "missing.py")

    assert codes(ENGINE.scan_path(tmp_path / "ghost.py")) == [TARGET_SYMLINK]


def test_links_in_parent_directories_are_resolved_by_the_system(tmp_path):
    write(tmp_path / "real" / "m.py")
    make_symlink(tmp_path / "alias", "real", directory=True)

    result = ENGINE.scan_path(tmp_path / "alias" / "m.py")

    assert result.status is ScanStatus.COMPLETE
    assert finding_files(result) == ["m.py"]


# -- junctions -----------------------------------------------------


class FakeEntry:
    """A DirEntry stand-in, so link-like entries can be tested everywhere."""

    def __init__(self, real, info=None, stat_error=None):
        self._real = real
        self._info = info
        self._stat_error = stat_error
        self.name = real.name
        self.path = real.path

    def stat(self, *, follow_symlinks=True):
        if self._stat_error is not None:
            raise self._stat_error

        if self._info is not None:
            return self._info

        return self._real.stat(follow_symlinks=follow_symlinks)

    def is_dir(self, *, follow_symlinks=True):
        return self._real.is_dir(follow_symlinks=follow_symlinks)


class Listing:
    def __init__(self, entries):
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *exc):
        return False


def patch_scandir(monkeypatch, replace):
    """Wrap os.scandir, letting ``replace(path, entries)`` change a listing."""

    real = os.scandir

    def fake(path="."):
        with real(path) as iterator:
            entries = list(iterator)

        return Listing(replace(str(path), entries))

    monkeypatch.setattr(os, "scandir", fake)


def junction_info(real_stat):
    return SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o755,
        st_reparse_tag=engine_module.IO_REPARSE_TAG_MOUNT_POINT,
        st_dev=real_stat.st_dev,
    )


def test_a_junction_like_directory_is_skipped_with_a_warning(tmp_path, monkeypatch):
    write(tmp_path / "linked" / "m.py")
    write(tmp_path / "ok.py")

    def replace(path, entries):
        return [
            FakeEntry(e, junction_info(e.stat())) if e.name == "linked" else e
            for e in entries
        ]

    patch_scandir(monkeypatch, replace)

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["ok.py"]
    assert issue_files(result) == [(SYMLINK_SKIPPED, "linked")]


def test_an_explicit_junction_like_target_is_not_followed(tmp_path, monkeypatch):
    write(tmp_path / "m.py")
    real = os.lstat

    def fake(path, *args, **kwargs):
        info = real(path, *args, **kwargs)

        if os.fspath(path) == str(tmp_path):
            return junction_info(info)

        return info

    monkeypatch.setattr(os, "lstat", fake)

    result = ENGINE.scan_path(tmp_path)

    assert codes(result) == [TARGET_SYMLINK]
    assert result.status is ScanStatus.FAILED


@pytest.mark.skipif(sys.platform != "win32", reason="needs Windows junctions")
def test_a_real_windows_junction_is_skipped(tmp_path):
    write(tmp_path / "real" / "m.py")
    outcome = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(tmp_path / "alias"), str(tmp_path / "real")],
        capture_output=True,
        check=False,
    )

    if outcome.returncode != 0:
        pytest.skip("cannot create a junction here")

    result = ENGINE.scan_path(tmp_path)

    assert finding_files(result) == ["real/m.py"]
    assert issue_files(result) == [(SYMLINK_SKIPPED, "alias")]
    assert codes(ENGINE.scan_path(tmp_path / "alias")) == [TARGET_SYMLINK]


# -- traversal errors ----------------------------------------------


def test_a_subdirectory_that_cannot_be_listed_is_a_walk_error(tmp_path, monkeypatch):
    write(tmp_path / "ok.py")
    write(tmp_path / "locked" / "hidden.py")
    real = os.scandir

    def fake(path="."):
        if str(path).endswith("locked"):
            raise PermissionError(13, "Permission denied", str(path))

        return real(path)

    monkeypatch.setattr(os, "scandir", fake)

    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.PARTIAL
    assert issue_files(result) == [(WALK_ERROR, "locked")]
    assert result.issues[0].level is IssueLevel.ERROR
    assert result.issues[0].message == "Permission denied"
    assert finding_files(result) == ["ok.py"]


def test_a_nested_directory_error_names_its_relative_path(tmp_path, monkeypatch):
    write(tmp_path / "a" / "b" / "locked" / "x.py")
    real = os.scandir

    def fake(path="."):
        if str(path).endswith("locked"):
            raise OSError(5, "Input/output error", str(path))

        return real(path)

    monkeypatch.setattr(os, "scandir", fake)

    result = ENGINE.scan_path(tmp_path)

    assert issue_files(result) == [(WALK_ERROR, "a/b/locked")]


def test_an_unreadable_root_directory_has_failed(tmp_path, monkeypatch):
    write(tmp_path / "ok.py")
    real = os.scandir

    def fake(path="."):
        if str(path) == str(tmp_path):
            raise PermissionError(13, "Permission denied", str(path))

        return real(path)

    monkeypatch.setattr(os, "scandir", fake)

    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.FAILED
    assert issue_files(result) == [(WALK_ERROR, ".")]
    assert NO_PYTHON_FILES not in codes(result)


def test_an_entry_that_cannot_be_inspected_is_a_walk_error(tmp_path, monkeypatch):
    write(tmp_path / "ok.py")
    write(tmp_path / "odd.py")

    def replace(path, entries):
        return [
            FakeEntry(e, stat_error=OSError(5, "Input/output error"))
            if e.name == "odd.py"
            else e
            for e in entries
        ]

    patch_scandir(monkeypatch, replace)

    result = ENGINE.scan_path(tmp_path)

    assert result.status is ScanStatus.PARTIAL
    assert issue_files(result) == [(WALK_ERROR, "odd.py")]
    assert finding_files(result) == ["ok.py"]


def test_an_error_in_the_middle_of_a_listing_is_not_lost(tmp_path, monkeypatch):
    write(tmp_path / "locked" / "x.py")
    real = os.scandir

    class Failing:
        def __enter__(self):
            def broken():
                raise OSError(5, "Input/output error")
                yield  # pragma: no cover

            return broken()

        def __exit__(self, *exc):
            return False

    def fake(path="."):
        if str(path).endswith("locked"):
            return Failing()

        return real(path)

    monkeypatch.setattr(os, "scandir", fake)

    assert issue_files(ENGINE.scan_path(tmp_path)) == [(WALK_ERROR, "locked")]
