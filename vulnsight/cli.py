"""Command-line interface: ``vulnsight scan PATH``.

This module only parses arguments, calls ``ScanEngine``, renders the result and
sets the exit code. It contains no scanning logic.

Exit codes:

* 0: the scan is complete and found nothing.
* 1: the scan is complete and reported findings.
* 2: usage error.
* 3: the scan is partial (some files could not be analysed).
* 4: the scan failed, the report could not be written, or VulnSight hit an
  internal error.
"""

import argparse
import os
import secrets
import sys

from vulnsight.engine import ScanEngine, discover_files, installed_version
from vulnsight.scan_result import IssueLevel, ScanStatus
from vulnsight.scanner.policy import ParameterMode

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3
EXIT_FAILED = 4

MEMORY = "<memory>"


def build_parser():
    """Build the argument parser."""

    parser = argparse.ArgumentParser(
        prog="vulnsight",
        description="Hybrid AI-based code vulnerability detection.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"vulnsight {installed_version() or 'unknown'}",
    )

    commands = parser.add_subparsers(dest="command", required=True, metavar="command")
    scan = commands.add_parser(
        "scan",
        help="scan a Python file or directory",
        description=(
            "Scan a Python file, or a directory recursively, for potential "
            "vulnerabilities. A file named explicitly is scanned whatever its "
            "extension. Symbolic links are not followed."
        ),
    )
    scan.add_argument("path", metavar="PATH", help="a file or directory to scan")
    scan.add_argument(
        "--parameter-mode",
        choices=[mode.value for mode in ParameterMode],
        default=ParameterMode.STRICT.value,
        help=(
            "strict (default): function parameters are clean. recall "
            "(experimental): parameters of module-level functions and class "
            "methods are tainted, with low-confidence findings"
        ),
    )
    scan.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    scan.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of standard output",
    )

    return parser


# -- rendering ------------------------------------------------------


def _where(file, line=None, column=None):
    text = file if file is not None else MEMORY

    if line is not None:
        text = f"{text}:{line}"

        if column is not None:
            text = f"{text}:{column}"

    return text


def _finding_block(finding):
    location = finding.location
    where = _where(location.file, location.line, location.column + 1)
    callee = finding.sink.callee if finding.sink is not None else "-"
    effect = finding.taint_effect.value if finding.taint_effect else "none"

    lines = [
        f"{where}: {finding.rule_id} {finding.cwe} "
        f"[{finding.confidence.value}, {effect}] {callee}",
        f"    {finding.message}",
    ]

    origins = [
        f"{label.origin.origin_id} (line {label.origin.line})"
        for label in finding.evidence
    ]

    if origins:
        lines.append("    Evidence: " + ", ".join(origins))

    return "\n".join(lines)


def _issue_line(issue):
    parts = [f"{issue.level.value:<7}", issue.code]

    if issue.file is not None:
        parts.append(_where(issue.file, issue.line))

    parts.append(issue.message)

    return "  " + "  ".join(parts)


def format_text(result):
    """Render a ScanResult as the human-readable report.

    Columns are 1-based here (JSON keeps the schema's 0-based columns). A
    location without a file, as for in-memory source, is shown as ``<memory>``.
    """

    settings = result.metadata.settings_dict()
    errors = sum(1 for issue in result.issues if issue.level == IssueLevel.ERROR)
    warnings = len(result.issues) - errors
    scanned = result.metadata.files_scanned or 0

    sections = [
        "\n".join(
            [
                "VulnSight scan",
                f"Target: {result.target if result.target is not None else MEMORY}",
                f"Parameter mode: {settings.get('parameter_mode', 'unknown')}",
            ]
        )
    ]

    if result.findings:
        sections.append("\n\n".join(_finding_block(f) for f in result.findings))
    else:
        sections.append("No findings.")

    if result.issues:
        sections.append(
            "\n".join(["Issues:", *(_issue_line(issue) for issue in result.issues)])
        )

    sections.append(
        f"Summary: {len(result.findings)} finding(s), {scanned} file(s) scanned, "
        f"{errors} error(s), {warnings} warning(s). "
        f"Status: {result.status.value}"
    )

    return "\n\n".join(sections) + "\n"


def exit_code(result):
    """Map a ScanResult to the process exit code."""

    if result.status == ScanStatus.FAILED:
        return EXIT_FAILED

    if result.status == ScanStatus.PARTIAL:
        return EXIT_PARTIAL

    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


# -- output ---------------------------------------------------------


def _write_report(path, text):
    """Write the report to ``path`` without ever leaving a partial file.

    The text is written to a temporary file in the same directory and then
    moved over the destination, so an existing file is replaced only by a
    complete report, and is left alone when anything fails. The file is UTF-8
    with LF line endings and no byte order mark.
    """

    data = text.encode("utf-8", "replace")
    directory = os.path.dirname(os.path.abspath(path))
    temporary = os.path.join(
        directory, f".{os.path.basename(path)}.{secrets.token_hex(4)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, 0o666)

    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)

        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass

        raise


def _identical(first, second):
    """Check whether two paths name the same file.

    This sees through symbolic links, hard links, different spellings of one
    path (``a/./b``, ``a/../a/b``), links in parent directories and, on case
    insensitive file systems, differences in letter case. A path that does not
    exist is not identical to anything. When the file system gives no file
    identity (an inode number of 0), the resolved paths are compared instead.
    """

    try:
        first_stat = os.stat(first)
        second_stat = os.stat(second)
    except OSError:
        return False

    if first_stat.st_ino and second_stat.st_ino:
        return os.path.samestat(first_stat, second_stat)

    def resolved(path):
        return os.path.normcase(os.path.realpath(path))

    return resolved(first) == resolved(second)


def _overwritten_source(output, path):
    """Return a scanned file that writing ``output`` would overwrite, or None.

    The scanned files are chosen by ``discover_files``, which uses the engine's
    own rules (extensions, skipped directories, link handling). The check also
    covers the scan target itself. A report inside a scanned directory is
    fine as long as it is not one of the scanned files. It runs before the
    scan, so files created or links changed during the scan are not rechecked.
    """

    if _identical(output, path):
        return path

    for scanned in discover_files(path):
        if _identical(output, scanned):
            return scanned

    return None


def _prepare_streams():
    """Show characters a console cannot encode instead of crashing."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)

        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (OSError, ValueError):
                pass


def _error(message):
    print(f"vulnsight: error: {message}", file=sys.stderr)


def _internal_error(error):
    _error(f"internal error ({type(error).__name__}): {str(error) or 'no details'}")

    return EXIT_FAILED


def _usage_error(parser, message):
    parser.print_usage(sys.stderr)
    _error(message)

    return EXIT_USAGE


# -- entry point ----------------------------------------------------


def main(argv=None):
    """Run the command line. Returns the process exit code."""

    parser = build_parser()

    try:
        arguments = parser.parse_args(argv)
    except SystemExit as stop:
        code = stop.code

        if code is None:
            return 0

        return code if isinstance(code, int) else EXIT_USAGE

    _prepare_streams()

    if not arguments.path or "\x00" in arguments.path:
        return _usage_error(parser, "PATH must be a non-empty path")

    if arguments.output is not None:
        if not arguments.output or "\x00" in arguments.output:
            return _usage_error(parser, "--output must be a non-empty path")

        try:
            protected = _overwritten_source(arguments.output, arguments.path)
        except Exception as error:
            return _internal_error(error)

        if protected is not None:
            return _usage_error(
                parser,
                f"--output would overwrite a file that is being scanned: {protected}",
            )

    try:
        engine = ScanEngine(parameter_mode=ParameterMode(arguments.parameter_mode))
        result = engine.scan_path(arguments.path)
        text = _render(result, arguments.format)
    except Exception as error:
        return _internal_error(error)

    if arguments.output is None:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except OSError as error:
            _error(f"cannot write report to standard output: {error.strerror}")

            return EXIT_FAILED
        except Exception as error:
            return _internal_error(error)
    else:
        try:
            _write_report(arguments.output, text)
        except OSError as error:
            _error(
                f"cannot write report to '{arguments.output}': "
                f"{error.strerror or type(error).__name__}"
            )

            return EXIT_FAILED
        except Exception as error:
            return _internal_error(error)

        print(f"Report written to {arguments.output}", file=sys.stderr)

    return exit_code(result)


def _render(result, report_format):
    if report_format == "json":
        text = result.to_json()

        return text if text.endswith("\n") else text + "\n"

    return format_text(result)
