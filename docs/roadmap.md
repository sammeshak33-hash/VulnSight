# VulnSight Roadmap

Status: M0, M0.1, M0.2 and M1.1 complete. PR #4 (taint propagation through method receivers, an approved engine exception) is merged. M1.2 implemented and locally validated; pending review/merge. M1.3 starts after M1.2 is merged.

## Workflow

- One module at a time. One feature branch and one pull request per module.
- Every module ships implementation, tests, documentation and validation.
- Dependencies are strict: a module starts only when the modules it depends on are merged.

## Project decisions

- Parameter taint mode: `strict` is the default. `recall` is experimental, for high-recall candidate generation for the ML verifier.
- The taint engine is frozen except for the changes approved in M1.3 and M4.3, and for evidence-triggered modules X1 to X3. One further exception was approved and is merged: PR #4 fixed taint propagation through method-call receivers. It changed `visitor.py` (receiver propagation), and added the `SourceSpec.container` declaration in `specs.py` and `policy.py` so that `get()` and `copy()` propagate only from declared container sources.
- The research core has priority. Features outside it are cut first.
- Primary Python dataset: CVEfixes (v1.0.8 on Zenodo, a SQL dump). Fallback: GitHub Advisory / OSV with fix commits. Availability, dump format, licence and Python share are verified in M3.1 before the choice is final.
- Hardware: local NVIDIA RTX 4050 Laptop GPU, with Colab or Kaggle as backup.

## Milestones

| Milestone | Goal | Modules |
|---|---|---|
| M1 Integration | Engine becomes a scanner with an evidence-carrying output | 4 |
| M2 Evaluation and baselines | Metrics, benchmark, Bandit and Semgrep baselines | 3 |
| M3 Dataset preparation | Normalized, leak-free Python dataset | 2 |
| M4 Python detection breadth | Rules and sources chosen from the dataset's CWE distribution | 4 |
| M5 Alert corpus and ML verification | The research core | 7 |
| M6 C/C++ | Tree-sitter patterns, Cppcheck, data, verifier | 5 |
| M7 Severity | CVSS v4.0 engine, estimator, evaluation | 3 |
| M8 Explanation, fixes, reporting | Explanations, recommendations, fix verification, SARIF | 4 |
| M9 Release and research | CI matrix, docs, paper, hardening, v1.0 | 4 |

Total: 36 modules. Tiers: A = research floor (19), B = research claims (+5), C = full Python product (+7), D = C/C++ (+5).

## Modules

Format: ID, name, complexity, tier, dependencies, key outputs.

### M1 Integration
- **M1.1 Finding v2 and ScanResult**. Low, A. After M0.2. `findings.py`, `scan_result.py`, `codec.py`, `docs/finding-schema.md`. Fingerprint has three parts (see Design notes).
- **M1.2 Detector migration**. Medium, A. After M1.1. CWE-78 runs on `TaintVisitor`; `taint.py` deleted; differential tests.
- **M1.3 Parameter modes**. Low, A. After M1.2. `ParameterMode`, `SourceKind.PARAMETER`, parameter binding only.
- **M1.4 ScanEngine and CLI**. Medium, A. After M1.2, M1.3. `engine.py`, `cli.py`, `vulnsight scan`.

### M2 Evaluation and baselines
- **M2.1 Evaluation core and benchmark schema**. Medium, A. After M1.1. `eval/metrics.py`, `eval/benchmark.py`.
- **M2.2 Micro-benchmark and `eval` command**. Medium, A. After M2.1, M1.3, M1.4. At least 60 CWE-78 cases; baseline report.
- **M2.3 Bandit and Semgrep adapters**. Medium, A. After M2.2. Recorded-fixture tests; optional extra.

### M3 Dataset preparation
- **M3.1 Python dataset ingestion**. High, A. After M2.1. CVEfixes to normalized function-level pairs; CWE-distribution report.
- **M3.2 Splits, deduplication, leakage control**. Medium, A. After M3.1. Grouped splits; leakage audit test.

### M4 Python detection breadth
- **M4.1 Rule-pack infrastructure, CWE-95, CWE-502**. Medium, A. After M1.4, M2.2.
- **M4.2 CWE-89 and CWE-22**. Medium, A. After M4.1.
- **M4.3 Framework sources and entry points**. Medium, A. After M4.1, M1.3. Approved engine change: route-decorated parameters tainted.
- **M4.4 CWE-79 and CWE-798**. Medium, C. After M4.1. Promoted to A if the dataset shows CWE-79 or CWE-798 dominate.

### M5 Alert corpus and ML verification
- **M5.1 Alert generation and labelling**. High, A. After M3.2, M4.x, M2.3. Pilot of 300 audited alerts before scaling.
- **M5.2 Feature extraction**. Medium, A. After M5.1. Versioned `FeatureSpec`; leakage guard.
- **M5.3 Tabular verifier**. Medium, A. After M5.2.
- **M5.4 Code slicer**. Medium, A. After M5.1.
- **M5.5 CodeBERT verifier**. High, A. After M5.4, M5.3.
- **M5.6 Verifier integration**. Medium, A. After M5.3, M1.4. Fail-open; suppressed findings stay visible.
- **M5.7 Research evaluation and ablations**. High, A. After M5.5, M5.6.

### M6 C/C++
- **M6.1 Tree-sitter parsing**. Medium, D. After M1.4.
- **M6.2 C/C++ pattern detector**. Medium, D. After M6.1, M4.4's `PatternRule`.
- **M6.3 Cppcheck adapter**. Low, D. After M2.3.
- **M6.4 C/C++ dataset and labelling**. High, D. After M6.2, M5.1, M3.2.
- **M6.5 C/C++ verifier and cross-language evaluation**. Medium, D. After M6.4, M5.7.

### M7 Severity
- **M7.1 CVSS v4.0 engine**. High, B. After M1.1. Matches published reference vectors exactly.
- **M7.2 Context-aware estimator**. Medium, B. After M7.1, M4.x.
- **M7.3 Severity evaluation**. Medium, B. After M7.2, M3.1.

### M8 Explanation, fixes, reporting
- **M8.1 Explanation generator**. Medium, C. After M1.1.
- **M8.2 Fix recommendations**. Medium, C. After M8.1.
- **M8.3 Fix verification**. High, B. After M5.6 (and M1.1). Does not depend on M8.2; dataset fix pairs supply its test data.
- **M8.4 Reports (JSON, Markdown, HTML, SARIF)**. Medium, C. After M8.1.

### M9 Release and research
- **M9.1 CI matrix and packaging**. Low, C. After M5.x.
- **M9.2 Documentation and demo**. Medium, C. After M8.4.
- **M9.3 Paper and reproducibility package**. High, B. After M5.7, M7.3, M8.3.
- **M9.4 Release hardening and v1.0.0**. Medium, C. After all.

### Conditional (only if evidence triggers them)
- **X1 Intra-file call summaries**. Trigger: M5.7 error analysis shows many missed true positives are cross-function within a file.
- **X2 Learned severity**. Trigger: M7.3 shows weak correlation.
- **X3 Loop fixed-point**. Trigger: error analysis shows loop-carried taint matters.

## Critical path

M1.1, M1.2, M1.3, M1.4, M2.1, M2.2, M2.3, then M3.1, M3.2 and the chosen M4 rules, then M5.1, M5.2, M5.3, M5.6, M5.7 (with M5.4 and M5.5 joining at M5.7), then M8.3 and M9.3.

Biggest schedule risk: M3.1 (dataset size, dump format, Python share). Biggest research risk: M5.1 (label quality).

## If time becomes limited

- **Tier A (19 modules)** is the minimum credible research result for Python: M1.1 to M1.4, M2.1 to M2.3, M3.1, M3.2, M4.1 to M4.3, M5.1 to M5.7.
- **Tier B (+5)** adds severity and fix verification with evaluation, plus the paper: M7.1 to M7.3, M8.3, M9.3.
- **Tier C (+7)** completes the Python product: M4.4, M8.1, M8.2, M8.4, M9.1, M9.2, M9.4.
- **Tier D (+5)** is C/C++. If time runs out, do M6.1 to M6.3 (detection only, no ML) and state the verifier as future work.
- Cut order: Tier D ML (M6.4, M6.5), then M4.4, then HTML reports, then M8.2.

## Design notes

### Fingerprints for fix verification

A finding carries three identifiers, because no single one survives both renames and moves:

1. `fingerprint`: hash of rule, CWE, canonical sink callee and enclosing qualname. Line-insensitive. Cross-scan grouping key. `finding_id` (fingerprint plus occurrence) is the scan-local unique id.
2. `evidence_signature`: rule, sink callee, and for each taint origin its id and trace-kind sequence, with origins in canonical order (sorted by origin id, then trace-kind sequence) so the signature does not depend on file position. Contains no file, line or function name. `None` when there is no taint evidence.
3. `structure_hash`: hash of the enclosing function's AST with local names renamed canonically (callee names, attribute names and constant shapes are kept).

`verify-fix` matches a before-finding to the after-version in tiers: exact fingerprint, then the same `structure_hash` or a high AST-shingle similarity (renamed function), then a unique `evidence_signature` within the changed files (moved code). An ambiguous match gives INCONCLUSIVE, never a guess. When a finding disappears, the verdict separates "sink removed" from "sink sanitized". Fix-pair patch hunks are used as extra evidence where available. M8.3 tests rename, move and reorder mutations.

### Leakage control in dataset splits

- Split unit is a group, built with union-find over repository, CVE, fix commit, and near-duplicate code. A CVE spanning repositories merges those repositories into one group.
- A vulnerable function and its fixed version are always in the same group. Alerts inherit the split of their source function.
- Exact duplicates are found by hashing normalized code (`ast.unparse`, comments and docstrings removed). Near-duplicates are found by token-shingle Jaccard similarity and merged into one group.
- Negative examples are sampled from the same repositories as positives and follow the same grouping.
- Primary evaluation uses the grouped split; a secondary time-based split uses CVE publication date.
- Thresholds are tuned on validation only; the test split is used once per reported experiment. Small data uses grouped cross-validation.
- The M3.2 audit test asserts empty intersections for repository, CVE, commit and code-hash sets across splits. M5.2 bans repository-identifying features.
- Known residual risk: pretrained models may have seen these repositories. This goes into the paper's threats to validity.
