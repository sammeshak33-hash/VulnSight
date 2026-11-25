"""Scan engine: turn a Python source string, file or directory into a ScanResult.

The engine owns everything about *what* is scanned: reading files, walking
directories, parsing, running the CWE-78 detector and collecting problems as
issues. It never prints, never exits and never reads ``sys.argv``. The command
line (``vulnsight.cli``) is a thin layer on top.

Scanned code is only parsed with ``ast.parse``. It is never imported, compiled
to bytecode or executed.

Failure contract: ``scan_source`` and ``scan_path`` return a ``ScanResult`` for
every problem that comes from the scanned input or the environment (syntax
errors, bad encodings, unreadable files, missing targets, symlinks, traversal
errors, crashes while analysing). They raise ``ValueError`` only for invalid
arguments.
"""

import ast
import io
import os
import stat
import tokenize
import warnings
from dataclasses import dataclass
from importlib import metadata

from vulnsight.findings import assign_occurrences, normalize_path
from vulnsight.scan_result import (
    IssueLevel,
    ScanIssue,
    ScanMetadata,
    ScanResult,
    ScanStatus,
)
from vulnsight.scanner import command_injection
from vulnsight.scanner.policy import ParameterMode, create_default_policy

PYTHON_SUFFIX = ".py"

# Directories that are never entered during a directory scan. They hold version
# control data, virtual environments, caches and third-party packages, not the
# project's own code. Skipping them is silent.
SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)

# Issue codes. They are free text in the schema; these are the ones the engine
# produces. See docs/scanning.md.
SYNTAX_ERROR = "syntax-error"
ENCODING_ERROR = "encoding-error"
ANALYSIS_ERROR = "analysis-error"
READ_ERROR = "read-error"
WALK_ERROR = "walk-error"
TARGET_NOT_FOUND = "target-not-found"
TARGET_UNREADABLE = "target-unreadable"
TARGET_SYMLINK = "target-symlink"
TARGET_UNSUPPORTED = "target-unsupported"
SYMLINK_SKIPPED = "symlink-skipped"
NO_PYTHON_FILES = "no-python-files"

# Windows reparse tag of a directory junction (a "mount point"). The ``stat``
# module only defines it on Windows, so the documented value is used here.
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003


def installed_version():
    """Return the installed version of vulnsight, or ``None`` if not installed."""

    try:
        return metadata.version("vulnsight") or None
    except metadata.PackageNotFoundError:
        return None


def is_link_like(info):
    """Check whether a ``stat`` result (not following links) is a link.

    True for a symbolic link, and for a Windows directory junction. A junction
    is not a symbolic link, but it redirects a directory just the same, so it
    is treated the same way. Both Python 3.11 and later report the reparse tag
    in ``st_reparse_tag`` on Windows, which is what is used here. Other
    reparse points (cloud placeholders, deduplicated files) are ordinary files
    and are not treated as links. On other platforms there is no tag, and only
    symbolic links count.
    """

    if stat.S_ISLNK(info.st_mode):
        return True

    return getattr(info, "st_reparse_tag", 0) == IO_REPARSE_TAG_MOUNT_POINT


def _safe_text(text):
    """Make text encodable as UTF-8.

    A file name that is not valid in the file system's encoding arrives with
    surrogate escapes. The undecodable bytes are shown as U+FFFD. A backslash
    escape is not used, because paths treat a backslash as a separator.
    """

    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")


def _path_text(text):
    return normalize_path(_safe_text(text))


def _without_trailing_separators(path):
    """Drop trailing separators, so a symlink typed as ``link/`` is detected.

    ``os.lstat("link/")`` follows the link on POSIX. A bare root (``/``) and a
    Windows drive root (``C:\\``) are left as they are.
    """

    separators = os.sep + (os.altsep or "")
    stripped = path.rstrip(separators)

    if not stripped or stripped.endswith(":"):
        return path

    return stripped


def _issue(level, code, message, file=None, line=None):
    return ScanIssue(
        level=level,
        code=code,
        message=_safe_text(message) or code,
        file=file,
        line=line,
    )


def _os_message(error):
    """A short, machine-independent text for an OSError (no file paths)."""

    return error.strerror or type(error).__name__


@dataclass(frozen=True, slots=True)
class _Unit:
    """The outcome of analysing one source text."""

    findings: tuple = ()
    issues: tuple = ()
    analyzed: bool = False


class ScanEngine:
    """Scan Python source, files and directories.

    ``parameter_mode`` chooses how function parameters are treated as taint
    sources (see ``vulnsight.scanner.policy.ParameterMode``). The mode is
    recorded in ``ScanMetadata.settings["parameter_mode"]`` of every result.
    """

    def __init__(self, *, parameter_mode=ParameterMode.STRICT):
        if not isinstance(parameter_mode, ParameterMode):
            raise ValueError("parameter_mode must be a ParameterMode")

        self._parameter_mode = parameter_mode
        self._policy = create_default_policy(parameter_mode)
        self._tool_version = installed_version()

    @property
    def parameter_mode(self):
        return self._parameter_mode

    # -- in-memory source ------------------------------------------

    def scan_source(self, source, *, file=None):
        """Scan Python source held in memory.

        ``source`` is a non-empty ``str`` or ``bytes`` (an empty value raises
        ``ValueError``; an empty file on disk is still scanned by
        ``scan_path``). ``file`` is an optional name
        recorded on findings and issues; it is never opened. Without it,
        findings and issues have ``file=None``, as for all in-memory source.

        The result has ``target=None``. ``files_scanned`` is 1 when the source
        was analysed and 0 when it was not. The status is ``COMPLETE`` or
        ``FAILED``, never ``PARTIAL``, because there is a single unit.
        """

        if not isinstance(source, str | bytes):
            raise ValueError("source must be str or bytes")

        if not source:
            raise ValueError("source must not be empty")

        display = None

        if file is not None:
            if not isinstance(file, str) or not file:
                raise ValueError("file must be a non-empty string or None")

            display = _path_text(file)

        unit = self._analyze(source, display)

        return self._build(None, [unit])

    # -- files and directories -------------------------------------

    def scan_path(self, path):
        """Scan a file or a directory.

        A file named explicitly is scanned whatever its extension. A directory
        is searched recursively for ``*.py`` files. Symbolic links (and
        Windows junctions) are never followed, including an explicit target.

        Paths in findings and issues are relative to a directory target, or the
        file's own name for a file target, always with ``/`` separators.
        ``ScanResult.target`` is the path as given, with ``/`` separators.
        """

        target = _resolve_target(path)

        if target.kind == _FAILED:
            return self._target_failure(target.text, target.code, target.message)

        if target.kind == _FILE:
            name = _path_text(os.path.basename(target.location))
            units = [self._scan_file(target.location, name)]

            return self._build(target.text, units)

        return self._scan_directory(target.text, target.location)

    # -- internals -------------------------------------------------

    def _target_failure(self, target, code, message):
        issue = _issue(IssueLevel.ERROR, code, message)

        return self._build(target, [_Unit(issues=(issue,))])

    def _scan_directory(self, target, root):
        files, issues = _walk(root)
        units = [_Unit(issues=tuple(issues))]

        if not files and not any(i.level == IssueLevel.ERROR for i in issues):
            warning = _issue(
                IssueLevel.WARNING,
                NO_PYTHON_FILES,
                "no Python files were found in the directory",
            )
            units.append(_Unit(issues=(warning,)))

        for display, location in sorted(files):
            units.append(self._scan_file(location, display))

        return self._build(target, units)

    def _scan_file(self, location, display):
        try:
            with open(location, "rb") as handle:
                data = handle.read()
        except OSError as error:
            issue = _issue(
                IssueLevel.ERROR, READ_ERROR, _os_message(error), file=display
            )

            return _Unit(issues=(issue,))

        return self._analyze(data, display)

    def _analyze(self, source, display):
        """Decode, parse and analyse one source text. Never raises."""

        def failure(code, message, line=None):
            issue = _issue(IssueLevel.ERROR, code, message, display, line)

            return _Unit(issues=(issue,))

        text = source

        if isinstance(source, bytes):
            try:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
                text = source.decode(encoding)
            except SyntaxError as error:
                return failure(ENCODING_ERROR, error.msg or str(error))
            except (UnicodeDecodeError, LookupError) as error:
                return failure(ENCODING_ERROR, str(error))

        try:
            with warnings.catch_warnings():
                # Scanned code can contain things Python warns about (such as
                # invalid escape sequences). Those are not VulnSight output.
                warnings.simplefilter("ignore")
                tree = ast.parse(text)
        except SyntaxError as error:
            line = error.lineno if isinstance(error.lineno, int) else None

            if line is not None and line < 1:
                line = None

            return failure(SYNTAX_ERROR, error.msg or str(error), line)
        except ValueError as error:
            return failure(SYNTAX_ERROR, str(error))
        except Exception as error:  # RecursionError, MemoryError and so on
            return failure(ANALYSIS_ERROR, _describe(error))

        try:
            findings = command_injection.detect(tree, file=display, policy=self._policy)
        except Exception as error:
            return failure(ANALYSIS_ERROR, _describe(error))

        return _Unit(findings=tuple(findings), analyzed=True)

    def _build(self, target, units):
        findings = [finding for unit in units for finding in unit.findings]
        issues = [issue for unit in units for issue in unit.issues]
        analyzed = sum(1 for unit in units if unit.analyzed)
        has_errors = any(issue.level == IssueLevel.ERROR for issue in issues)

        if not has_errors:
            status = ScanStatus.COMPLETE
        elif analyzed:
            status = ScanStatus.PARTIAL
        else:
            status = ScanStatus.FAILED

        return ScanResult(
            status=status,
            target=target,
            # Occurrences are numbered per fingerprint over all files at once,
            # so finding ids stay unique across files.
            findings=assign_occurrences(findings),
            issues=tuple(issues),
            metadata=ScanMetadata.with_settings(
                {"parameter_mode": self._parameter_mode.value},
                files_scanned=analyzed,
                tool_version=self._tool_version,
            ),
        )


_FILE = "file"
_DIRECTORY = "directory"
_FAILED = "failed"


@dataclass(frozen=True, slots=True)
class _Target:
    """What a scan target is, decided once for every user of the rules."""

    text: str
    kind: str
    location: str | None = None
    code: str | None = None
    message: str | None = None


def _resolve_target(path):
    """Classify a scan target. Raises ``ValueError`` for invalid arguments.

    This is the single place that decides what ``scan_path`` does with a
    target (file, directory or failure), so ``discover_files`` cannot drift
    from it.
    """

    try:
        raw = os.fspath(path)
    except TypeError:
        raise ValueError("path must be a string or path-like object") from None

    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)

    if not raw:
        raise ValueError("path must not be empty")

    if "\x00" in raw:
        raise ValueError("path must not contain a null character")

    text = _path_text(raw)
    location = _without_trailing_separators(raw)

    def failed(code, message):
        return _Target(text, _FAILED, code=code, message=message)

    try:
        info = os.lstat(location)
    except (FileNotFoundError, NotADirectoryError):
        return failed(TARGET_NOT_FOUND, "target does not exist")
    except OSError as error:
        return failed(TARGET_UNREADABLE, _os_message(error))

    if is_link_like(info):
        return failed(
            TARGET_SYMLINK,
            "target is a symbolic link; symbolic links are not followed",
        )

    if stat.S_ISREG(info.st_mode):
        return _Target(text, _FILE, location)

    if stat.S_ISDIR(info.st_mode):
        return _Target(text, _DIRECTORY, location)

    return failed(
        TARGET_UNSUPPORTED,
        "target is neither a regular file nor a directory",
    )


def discover_files(path):
    """List the files that ``scan_path(path)`` would read.

    Returns file system paths, in sorted order. The selection uses exactly the
    rules of ``scan_path``: an explicit file is included whatever its
    extension, a directory contributes its ``*.py`` files outside the skipped
    directories, and links are never followed. A target that cannot be scanned
    (missing, a link, unsupported) gives an empty result. Nothing is read or
    parsed, so this is cheap, and it never raises for the file system. It
    raises ``ValueError`` for the same invalid arguments as ``scan_path``.

    The command line uses this to refuse a report destination that would
    overwrite a file that is being scanned.
    """

    target = _resolve_target(path)

    if target.kind == _FILE:
        return (target.location,)

    if target.kind == _DIRECTORY:
        files, _ = _walk(target.location)

        return tuple(location for _, location in sorted(files))

    return ()


def _describe(error):
    return str(error) or type(error).__name__


def _walk(root):
    """List the Python files under ``root`` and the problems met on the way.

    Returns ``(files, issues)``. ``files`` holds ``(relative_path, location)``
    pairs. The walk is iterative, does not follow links, skips the directories
    in ``SKIPPED_DIRECTORIES`` silently, and turns every listing or ``stat``
    failure into a ``walk-error`` issue instead of ignoring it.
    """

    files = []
    issues = []
    pending = [("", root)]

    while pending:
        relative, directory = pending.pop()

        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            issues.append(
                _issue(
                    IssueLevel.ERROR,
                    WALK_ERROR,
                    _os_message(error),
                    file=_path_text(relative or "."),
                )
            )
            continue

        for entry in entries:
            name = _safe_text(entry.name)
            child = f"{relative}/{name}" if relative else name

            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                issues.append(
                    _issue(
                        IssueLevel.ERROR,
                        WALK_ERROR,
                        _os_message(error),
                        file=_path_text(child),
                    )
                )
                continue

            if is_link_like(info):
                if _link_matters(entry, info):
                    issues.append(
                        _issue(
                            IssueLevel.WARNING,
                            SYMLINK_SKIPPED,
                            "symbolic link not followed",
                            file=_path_text(child),
                        )
                    )

                continue

            if stat.S_ISDIR(info.st_mode):
                if entry.name not in SKIPPED_DIRECTORIES:
                    pending.append((child, entry.path))
            elif stat.S_ISREG(info.st_mode) and entry.name.endswith(PYTHON_SUFFIX):
                files.append((_path_text(child), entry.path))

    return files, issues


def _link_matters(entry, info):
    """Check whether a skipped link is worth a warning.

    A link is reported when it would otherwise have been scanned: its name ends
    in ``.py``, or it is a directory link. Other links to files or nowhere are
    ignored silently, because a directory scan would not read them anyway.
    """

    if entry.name.endswith(PYTHON_SUFFIX) or stat.S_ISDIR(info.st_mode):
        return True

    try:
        return entry.is_dir()
    except OSError:
        return False
