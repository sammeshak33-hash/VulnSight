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
| Scanner integration, `Finding` v2, CLI | Next (M1) |
| Evaluation, datasets, ML verification | Planned (M2 to M5) |
| C/C++, severity, explanations, fix verification | Planned (M6 to M8) |

There is no command-line tool yet. The current library entry points are `vulnsight.scanner.visitor.analyze_source` and `vulnsight.scanner.command_injection.scan_source`.

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
