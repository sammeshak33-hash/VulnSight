# Scanning: engine and command line (M1.4)

`vulnsight.engine.ScanEngine` scans Python source, files and directories and returns a `ScanResult` (schema 2.1, see [finding-schema.md](finding-schema.md)). `vulnsight.cli` is a thin command-line layer on top of it. Scanned code is only parsed with `ast.parse`. It is never imported, compiled to bytecode or executed.

## The command line

```
vulnsight scan PATH [--parameter-mode {strict,recall}] [--format {text,json}] [-o FILE | --output FILE]
vulnsight --version
python -m vulnsight scan PATH ...
```

| Option | Meaning |
|---|---|
| `PATH` | One file or directory. |
| `--parameter-mode` | `strict` (default) or `recall`. See [taint-analysis.md](taint-analysis.md). The mode is recorded in `ScanMetadata.settings["parameter_mode"]` of every result, strict included. |
| `--format` | `text` (default) or `json`. JSON is exactly `ScanResult.to_json()` plus one final newline. |
| `-o`, `--output FILE` | Write the report to FILE instead of standard output. |
| `--version` | Print `vulnsight <version>`, or `vulnsight unknown` if the package is not installed. |

`-` has no special meaning for `PATH` or `--output`. Standard input is not supported.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The scan is complete and found nothing. |
| 1 | The scan is complete and reported findings. |
| 2 | Usage error. |
| 3 | The scan is partial: some files could not be analysed. Findings may exist and are in the report. |
| 4 | The scan failed (nothing could be analysed), the report could not be written, or VulnSight hit an internal error. |

Warnings never change the exit code.

### Streams

The report goes to standard output, or to the file with `--output`. Usage errors and diagnostics go to standard error. With `--output`, standard output stays empty and standard error gets one line, `Report written to <path>`, after the report is safely in place. Characters a console cannot show are printed as escapes instead of crashing.

### Text report

```
VulnSight scan
Target: src
Parameter mode: strict

src/app.py:5:9: PY-CMD-001 CWE-78 [medium, raw] os.system
    Potential command injection: tainted data reaches os.system
    Evidence: input() (line 3)

Issues:
  error    syntax-error  bad.py:3  invalid syntax
  warning  symlink-skipped  link.py  symbolic link not followed

Summary: 1 finding(s), 3 file(s) scanned, 1 error(s), 1 warning(s). Status: partial
```

Columns in the text report are **1-based**. JSON keeps the schema's **0-based** columns. A location without a file (in-memory source) is shown as `<memory>`.

### Writing the report file

The report is rendered completely first, then written as UTF-8 with LF line endings and no byte order mark to a temporary file next to the destination, and moved into place. So:

- An existing report is replaced only by a complete new one. If anything fails, the old file is untouched and the temporary file is removed.
- A missing output directory is **not** created. The command prints `vulnsight: error: cannot write report to '<path>': <reason>` to standard error, writes nothing to standard output, prints no success line and exits 4. A path that is a directory, a file that cannot be created and a write that fails partway behave the same.
- A symbolic link at the output path is replaced, not written through. The new file gets the normal default permissions.
- **A report can never overwrite a file that is being scanned.** Before scanning, the command lists the files the scan will read with `vulnsight.engine.discover_files(PATH)`, which uses exactly the engine's rules (an explicit file whatever its extension; for a directory, `*.py` files outside the skipped directories; links never followed). If `--output` is one of them, or the scan target itself, the command prints `vulnsight: error: --output would overwrite a file that is being scanned: <file>` and exits 2 without scanning or writing anything. "Is one of them" means the same file, however it is reached: another spelling of the path (`src/./a.py`, `src/../src/a.py`, a relative path), a symbolic link or a chain of links, a hard link, a link in a parent directory, or a different letter case on a case-insensitive file system.
- A normal report inside the scanned directory is allowed (for example `src/report.json`), and so is replacing an existing non-source file. A `.py` file the scan does not read (inside a skipped directory, or a link that the scan skips and that points elsewhere) may also be replaced, because it is not being scanned.
- The check runs once, before the scan. Files created, or links changed, while the scan is running are not rechecked.

This option exists mainly because Windows PowerShell 5.1 redirection (`>`) writes UTF-16, which corrupts JSON.

## The engine

```python
from vulnsight.engine import ScanEngine
from vulnsight.scanner.policy import ParameterMode

engine = ScanEngine(parameter_mode=ParameterMode.STRICT)
result = engine.scan_path("src")  # file or directory
result = engine.scan_source(text_or_bytes, file=None)  # in-memory source
```

`ScanEngine.scan_source(source, *, file=None)` and `ScanEngine.scan_path(path)` follow one rule (`discover_files(path)` lists the files a scan would read, with the same rules, and raises `ValueError` for the same invalid paths):

- **Anything about the scanned input or the environment returns a `ScanResult`**, with ERROR issues. That covers syntax errors, bad encodings, unreadable files, a missing target, symbolic links, traversal errors and crashes while analysing.
- **Only invalid arguments raise `ValueError`**: a wrong type for `source`, an empty `source` (`""` or `b""`), a wrong type or empty value for `file` or `path`, a path with a null character, or a `parameter_mode` that is not a `ParameterMode`.
- `KeyboardInterrupt` is not caught.

`tool_version` is the installed distribution version, or `None` when the package is not installed. `created_at` is never set, so output is reproducible.

### Status and `files_scanned`

- `files_scanned` counts only files that were analysed successfully. A file with a syntax error is an issue and is not counted.
- Status is `complete` with no ERROR issue, `partial` with at least one ERROR issue and at least one file analysed, and `failed` with ERROR issues and no file analysed.

### In-memory scans

- `source` must not be empty. A blank or comment-only source is valid and gives an empty, complete result. An empty file on disk is also valid for `scan_path`.
- `file=None` gives findings and issues with `file=None`, as for all in-memory source (`Location.file` is `None`). `<memory>` appears only in the text report.
- A supplied `file` is normalized (`\` becomes `/`), recorded on findings and issues, and never opened.
- `target` is always `None`. `files_scanned` is 1 if the source was analysed and 0 if not. The status is `complete` or `failed`, never `partial`.

### Files and directories

- A **file** named explicitly is scanned whatever its extension. Findings use the file's base name as the path.
- A **directory** is searched recursively for files named `*.py` (case-sensitive). Paths are relative to the directory with `/` separators, and the walk is in sorted order, so the output does not depend on file system order or on the working directory.
- A directory with no Python files is `complete` with `files_scanned` 0 and a `no-python-files` warning.
- These directories are never entered, silently: `.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, `node_modules`, `.tox`, `.nox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`.
- `ScanResult.target` is the path as given, with `\` turned into `/`. It is not resolved, so a relative path stays relative.
- Findings from all files are numbered together, so `finding_id` values are unique across files.

### Symbolic links and junctions

Links are never followed, so a link cannot cause a loop or take the scan outside the target.

| Situation | Result |
|---|---|
| A link met during a directory scan whose name ends in `.py` (file link or broken link) | Skipped. WARNING `symlink-skipped`. |
| A link to a directory met during a directory scan | Not entered. WARNING `symlink-skipped`. |
| Any other link to a file or to nothing | Ignored silently (it would not have been scanned). |
| The explicit target is a link (file, directory or broken) | Not followed. Status `failed`, ERROR `target-symlink`, exit 4. |

Only the last part of the target path is checked. Links in parent directories are resolved by the operating system. A trailing separator (`link/`) is removed before checking, because `lstat("link/")` would follow the link.

**Windows junctions.** A junction is not a symbolic link, and Python 3.11 has no `is_junction()`. VulnSight uses the file's reparse tag instead: `os.lstat` and `DirEntry.stat(follow_symlinks=False)` report `st_reparse_tag` on Windows (Python 3.8 and later), and a value of `0xA0000003` (`IO_REPARSE_TAG_MOUNT_POINT`) is a junction. Junctions are then handled exactly like symlinks above. This works the same on Python 3.11 and later. Limitations:

- Only junctions and symbolic links are treated as links. Other reparse points (cloud placeholder files, deduplicated files) are ordinary files and are scanned normally.
- On other platforms only symbolic links exist as links. Bind mounts and hard-linked directories cannot be detected and could in principle make a walk loop.
- The detection logic is tested on every platform with simulated `stat` results. A test with a real junction (created with `mklink /J`) runs only on Windows.

### Issue codes

Issue codes are free text in the schema. These are the ones the engine produces.

| Code | Level | Meaning |
|---|---|---|
| `syntax-error` | error | The source does not parse (also null bytes). Has a line when known. |
| `encoding-error` | error | The bytes cannot be decoded, or the declared encoding is unknown or conflicts with a BOM. |
| `analysis-error` | error | Parsing or analysis raised something other than a syntax error, such as `RecursionError` on very deeply nested code. |
| `read-error` | error | A file could not be read. |
| `walk-error` | error | A directory could not be listed or an entry could not be inspected. The file is the directory's relative path (`.` for the target itself). |
| `target-not-found` | error | The target does not exist. |
| `target-unreadable` | error | The target could not be inspected (for example permission denied). |
| `target-symlink` | error | The target is a symbolic link or junction. |
| `target-unsupported` | error | The target is neither a regular file nor a directory (for example a named pipe). It is never opened. |
| `symlink-skipped` | warning | A symbolic link or junction was not followed. |
| `no-python-files` | warning | A directory had no Python files. |

Messages come from the operating system or Python without file paths, so they do not depend on where the project is.

## Limitations

- There is no file-size or time limit. A very large or adversarial file can use a lot of memory or time.
- The scan is sequential.
- File names that are not valid in the file system's encoding are shown with U+FFFD in place of the bad bytes.
- Only the CWE-78 detector exists. The engine calls it directly. Rule packs, the ML verifier hook, the `eval` command, other languages, other report formats, configuration files, baselines and standard input are later milestones.
