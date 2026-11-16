@'
# VulnSight

## Hybrid AI-Based Code Vulnerability Detection and Severity Assessment

VulnSight is an individual research and development project that aims to detect potential security vulnerabilities in Python and C/C++ source code.

The project combines traditional static analysis techniques with deep learning to identify suspicious code patterns, classify vulnerabilities, estimate severity, and provide understandable security recommendations.

## Objectives

- Detect common vulnerabilities in Python and C/C++.
- Identify vulnerability categories using CWE.
- Reduce false-positive alerts using AI-assisted analysis.
- Estimate vulnerability severity using CVSS.
- Explain findings and recommend secure coding practices.
- Verify whether proposed fixes address detected issues.

## Planned Technologies

- Python
- PyTorch
- CodeBERT
- Tree-sitter
- Bandit
- Semgrep
- Cppcheck
- pytest
- Ruff

## Planned Architecture

1. Source Code Parser
2. Static Analysis Engine
3. AI-Based Vulnerability Analysis
4. Finding Fusion and CWE Classification
5. CVSS Severity Estimation
6. Explanation and Fix Recommendation
7. Fix Verification
8. Security Report Generation

## Initial Vulnerability Categories

- CWE-78: OS Command Injection
- CWE-89: SQL Injection
- CWE-22: Path Traversal
- CWE-79: Cross-Site Scripting
- CWE-502: Deserialization of Untrusted Data
- CWE-798: Use of Hard-coded Credentials
- CWE-787: Out-of-bounds Write
- CWE-125: Out-of-bounds Read

## Research Focus

Investigate whether a deep-learning verification layer can reduce false-positive alerts from traditional static analysis while maintaining vulnerability detection recall.

## Project Status

**Phase 1: Environment Setup — Completed**

Implementation and evaluation are in progress.

## Development Setup

### 1. Clone the repository

```bash
git clone <repository-url>
cd VulnSight

```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate it on Windows

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install development dependencies

```bash
python -m pip install -e ".[dev]"
```

### 5. Run tests

```bash
python -m pytest
```

### 6. Check code quality

```bash
python -m ruff check .
```

## Important Note

VulnSight is an experimental research project. Its findings and severity estimates are intended to assist security analysis and should not be treated as proof that software is secure or insecure.

## Author

Developed as an individual AI and cybersecurity research project.