# VulnSight

## Hybrid AI-Based Code Vulnerability Detection and Severity Assessment

VulnSight is an individual research and development project that detects potential security vulnerabilities in Python and C/C++ source code.

It combines static analysis with machine learning to find suspicious code, classify it by CWE, estimate severity, explain the finding and check whether a proposed fix removes it.

## Research question

Can a machine-learning verification layer reduce the false-positive alerts of static analysis while keeping vulnerability detection recall?

## Objectives

- Detect common vulnerabilities in Python and C/C++.
- Identify vulnerability categories using CWE.
- Reduce false-positive alerts using an ML verification layer.
- Estimate vulnerability severity using CVSS v4.0.
- Explain findings and recommend secure coding practices.
- Verify whether a proposed fix addresses a detected issue.

## Current status

| Part | State |
|---|---|
| Core models, CWE catalog, rule registry | Done (M0, M0.1) |
| Python taint-analysis engine (`TaintVisitor`) | Done (M0.2) |
| `Finding` v2 and `ScanResult` models, JSON format | Done (M1.1). See [docs/finding-schema.md](docs/finding-schema.md) |
| Taint propagation through method-call receivers | Done (PR #4) |
| CWE-78 detector on the taint engine (detector migration) | Done (M1.2) |
| Parameter modes (strict and recall) | Done (M1.3) |
| Scan engine and `vulnsight scan` command | Done (M1.4). See [docs/scanning.md](docs/scanning.md) |
| Evaluation foundation (benchmark models, matching, precision, recall and F1) | Done (M2.1). See [docs/evaluation.md](docs/evaluation.md) |
| Local demonstration dashboard | Implemented; review complete, pending PR (M2.1a). A demonstration of the existing scanner, not an evaluation dependency. See [docs/dashboard.md](docs/dashboard.md) |
| Benchmark dataset, evaluation command, Bandit and Semgrep baselines | Planned (M2.2, M2.3) |
| Datasets, ML verification | Planned (M3 to M5) |
| C/C++, severity, explanations, fix verification | Planned (M6 to M8) |

## Usage

Scan a file or a directory (after `python -m pip install -e ".[dev]"`):

```powershell
vulnsight scan path\to\project
vulnsight scan path\to\project --format json --output report.json
vulnsight scan path\to\project --parameter-mode recall
python -m vulnsight scan path\to\file.py
```

`--parameter-mode strict` (the default) treats function parameters as clean. `recall` is experimental: it treats the parameters of module-level functions and class methods as untrusted and reports those findings with low confidence. Exit codes: 0 no findings, 1 findings, 2 usage error, 3 partial scan, 4 failed scan. The full command-line and engine reference is in [docs/scanning.md](docs/scanning.md).

### Local dashboard (M2.1a)

A small browser dashboard shows a scan of a directory or file on your own computer. It uses the same `ScanEngine` as the command line, adds no dependencies and listens on `127.0.0.1` only:

```powershell
python -m vulnsight.ui
python -m vulnsight.ui --port 9000 --no-browser
```

Open the printed address, enter a path, choose the parameter mode and click **Scan**. **Download JSON** saves exactly what `vulnsight scan PATH --format json` prints. The dashboard is a demonstration of the existing scanner; it shows no evaluation results. See [docs/dashboard.md](docs/dashboard.md).

Library entry points: `vulnsight.engine.ScanEngine` (returns a `ScanResult`), `vulnsight.scanner.command_injection.scan_source` (returns a list of `Finding` v2 objects, `vulnsight.Finding`) and `vulnsight.scanner.visitor.analyze_source` (the raw taint engine).

The full plan is in [docs/roadmap.md](docs/roadmap.md). How the taint engine works is described in [docs/taint-analysis.md](docs/taint-analysis.md).

## Planned architecture

1. Source code parsing
2. Static analysis engine (taint analysis for Python, pattern rules for C/C++)
3. ML-based verification of static alerts
4. Finding fusion and CWE classification
5. CVSS v4.0 severity estimation
6. Explanation and fix recommendation
7. Fix verification
8. Report generation

## Initial vulnerability categories

The final set will follow the CWE distribution of the dataset.

- CWE-78: OS Command Injection
- CWE-89: SQL Injection
- CWE-22: Path Traversal
- CWE-79: Cross-Site Scripting
- CWE-502: Deserialization of Untrusted Data
- CWE-798: Use of Hard-coded Credentials
- CWE-787: Out-of-bounds Write
- CWE-125: Out-of-bounds Read

## Development setup

```powershell
git clone https://github.com/sammeshak33-hash/VulnSight.git
cd VulnSight
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

## Development workflow

One feature branch and one pull request per module. Every module includes implementation, tests, documentation and validation. CI runs Ruff and pytest on Ubuntu and Windows.

## Important note

VulnSight is an experimental research project. Its findings and severity estimates assist security analysis and are not proof that software is secure or insecure.

## Author

Developed as an individual AI and cybersecurity research project.
