# Finding v2 and ScanResult

This document describes the result models added in M1.1.

Scope: these are data models and their JSON format. The current command-injection detector still produces the legacy `vulnsight.models.Finding`. Migrating the detector to the new engine is M1.2, and there is no scan command yet (M1.4).

| Module | Contents |
|---|---|
| `vulnsight/findings.py` | `Finding`, `Location`, `Sink`, `SeverityAssessment`, `Verification`, enums, `assign_occurrences`, `short_hash` |
| `vulnsight/scan_result.py` | `ScanResult`, `ScanIssue`, `ScanMetadata`, `ScanStatus`, `IssueLevel`, schema version constants |
| `vulnsight/codec.py` | `SchemaError`, strict JSON reader, canonical JSON writer, codecs for the taint-model types |

## Finding

`Finding` is a frozen dataclass. Taint evidence reuses the engine types `TaintLabel`, `TaintOrigin`, `TraceStep` and `Neutralization`, so nothing is stored twice.

| Field | Type | Meaning |
|---|---|---|
| `rule_id` | str | Rule identifier. Must not contain `\x1e` or `\x1f` |
| `cwe` | str | `CWE-<digits>` |
| `language` | `python`, `c`, `cpp` | |
| `message` | str | Human-readable summary |
| `location` | `Location` | File (or `None` for in-memory source), line, column, optional end position. Paths use `/` separators |
| `confidence` | `low`, `medium`, `high` | |
| `enclosing_function` | str or `None` | Qualified name. `"<module>"` at module level. `None` means unknown. `"<unknown>"` is reserved |
| `sink` | `Sink` or `None` | Callee and resolution certainty. `None` means the finding has no conventional sink. `"<no-sink>"` is reserved as a callee |
| `evidence` | tuple of `TaintLabel` | One per taint origin reaching the sink. Empty for non-taint findings. Stored in canonical order |
| `taint_effect` | `raw`, `partial` or `None` | Whether sanitizers fully or partly cover the target. `None` means not evaluated |
| `severity` | `SeverityAssessment` or `None` | `None` means not assessed. Fields: `level`, `method`, `score` (0 to 10), `vector`, `assumptions` |
| `verification` | `Verification` or `None` | `None` means ML verification did not run. Fields: `verdict` (`kept` or `suppressed`), `score` (0 to 1), `model_id` |
| `structure_hash` | 32 lowercase hex or `None` | Stored and validated only. Nothing in M1.1 computes it |
| `occurrence` | int, 0 or more | Position among findings with the same fingerprint in one scan |

Source information is the `origin` of each evidence label (id, kind, position). There is no separate source field. An explanation is not stored: it can be derived from the evidence.

### Structural rules

| `sink` | `evidence` | Valid | Example |
|---|---|---|---|
| none | empty | yes | Hard-coded credential |
| set | empty | yes | Banned-API pattern (for example C `strcpy`) |
| set | non-empty | yes | Taint flow |
| none | non-empty | no | A taint flow always ends at a sink |

`taint_effect` must be `None` when there is no evidence, and may only be `raw`, `partial` or `None`.

### Unknown versus genuine negative

`None` always means "unknown, absent or not produced". A real value is a real answer.

| Field | `None` means | A real value means |
|---|---|---|
| `severity` | not assessed | `SeverityLevel.NONE` is an assessed "no severity" |
| `verification` | ML not run | `kept` or `suppressed` |
| `taint_effect` | not evaluated | `raw` or `partial` |
| `sink` | no conventional sink | a callee |
| `enclosing_function` | unknown | `"<module>"` is module level |
| `evidence` (empty) | no taint-flow evidence | a taint trace |
| `structure_hash` | not computed | a hash |
| `location.file` | in-memory source | a path |
| `location.end_line`, `end_column` | unknown | numbers |
| `ScanMetadata.files_scanned` | unknown | `0` means nothing was scanned |
| `ScanMetadata.created_at` | not recorded | a UTC timestamp |

## Identifiers

All identifiers are SHA-256 digests, truncated to 32 lowercase hex characters. Inputs are joined with the character `\x1f`, and no input may contain it (or `\x1e`), so field boundaries are unambiguous. `fingerprint`, `evidence_signature` and `finding_id` are computed from the finding. They are not stored fields.

### `fingerprint`

Cross-scan grouping key. Hash of the prefix `vulnsight.fingerprint.v1` and these four inputs:

1. `rule_id`
2. `cwe`
3. the sink: `sink:<callee>`, or `no-sink` when the finding has no sink
4. the function: `function:<qualified name>`, or `function-unknown` when it is unknown

Line, column, file, message, confidence and evidence details are not part of it.

**Missing-sink safety.** A real sink always encodes with the `sink:` tag, and an absent sink encodes as `no-sink`, which has no colon. No callee, whatever it is spelled like, can produce the absent-sink encoding. `"<no-sink>"` and `"<unknown>"` are also rejected as names, so the human-readable placeholders cannot be mistaken for real values. The same reasoning applies to unknown functions (`function-unknown` versus `function:<name>`).

Limitation: two different non-sink findings of the same rule in the same function (for example two hard-coded credentials) share a fingerprint and are told apart only by `occurrence`. A `subject` field can be added when a real rule needs it.

### `evidence_signature`

Location-free summary of the taint evidence. `None` when there is no evidence. Otherwise the hash of the prefix `vulnsight.evidence-signature.v1`, the rule id, the sink encoding, and one entry per taint origin: the origin id and its trace-kind sequence, written `origin_id` + `\x1e` + comma-separated kinds.

Entries are sorted by origin id, then by trace-kind sequence, and duplicates are kept. This is the canonical reading of "ordered origin ids": it keeps the roadmap's intent (no file, line or function name in the signature) and does not depend on where an origin sits in the file. The engine's own label order breaks ties between same-id origins by position, which this signature deliberately does not.

### `finding_id`

`<fingerprint>-<occurrence>`. It is unique within one `ScanResult`, and it is **scan-local**. It is not a permanent identifier across scans: adding or removing an earlier finding with the same fingerprint changes the numbers. Match findings across scans with `fingerprint`, then `evidence_signature` and `structure_hash`.

### Occurrence assignment

`assign_occurrences(findings)` groups findings by fingerprint, orders each group by file path (plain string comparison), line, column, end line, end column and evidence signature, and numbers it from zero. The result depends only on the findings, never on input order or filesystem traversal order. Paths should be relative to the scan target. Two findings identical on every key raise `ValueError`. The returned tuple is in the canonical `ScanResult` order.

## ScanResult

| Field | Meaning |
|---|---|
| `schema_version` | `"2.0"` (a property, always the current version) |
| `target` | Scan target path, or `None` for in-memory source |
| `status` | `complete`, `partial` or `failed` |
| `findings` | Canonical order (file, line, column, rule, id). `finding_id` values must be unique |
| `issues` | `ScanIssue`: level (`error` or `warning`), code, message, optional file and line |
| `metadata` | `ScanMetadata`: `files_scanned`, `tool_version`, `created_at`, `settings` |

- `complete` allows warnings but no errors. `partial` and `failed` require at least one error.
- `settings` is a free-form string-to-string map. Keys are not defined by this module. The scan-wide parameter mode will be recorded here by a later module.
- The summary (counts of findings, errors, warnings, by CWE and by rule) is derived, never stored.
- Nothing in these modules reads, executes or imports scanned code.

## JSON format

`ScanResult.to_json()` returns UTF-8-safe text with sorted keys, two-space indentation, ASCII-only output (non-ASCII is escaped), LF line endings and no trailing newline. It contains no timestamp unless the caller set `created_at`, so the same result always produces the same text. `NaN` and infinity are rejected.

Top-level keys: `schema_version`, `target`, `status`, `findings`, `issues`, `metadata`, `summary`. Every key of every object is always present. Optional values are written as `null`, never omitted. Enums are written as their string values. Sets are written as sorted lists. Derived values (`fingerprint`, `evidence_signature`, `finding_id` and `summary`) are written for consumers.

Reading is strict:

- Invalid JSON, `NaN`, `Infinity` and non-object input raise `SchemaError`.
- Missing keys, unknown keys, wrong types (including booleans where numbers are expected), unknown enum values and values the models reject all raise `SchemaError`. The message names the path, for example `scan_result.findings[2].evidence[0].origin.kind`.
- Derived values are recomputed and compared. A mismatch means the document was edited or is corrupt, and is an error.
- A trace longer than the engine limit, or trace text longer than the model allows, is rejected, never truncated.
- Only `json` is used. Nothing is unpickled.

`SchemaError` is a subclass of `ValueError`. Object construction (`Finding(...)`, `ScanResult(...)`) raises plain `ValueError`.

## Schema versioning

`SCHEMA_VERSION` is `"2.0"`, and `SUPPORTED_SCHEMA_VERSIONS` lists exactly the versions this code can read. Anything else is rejected with a message naming the supported versions. The format is `MAJOR.MINOR`.

Because the reader is strict, every change to the serialized format is visible to older readers. Version changes are therefore **decided, not automatic**. Each change that touches the JSON format is assessed with these questions and the outcome is recorded in the changelog below:

1. Can documents produced with default settings contain the new value or key?
2. Does it change the meaning of existing data, or any identifier hash?
3. Does it make documents that were valid before invalid?

Rules:

- **Major bump** (`3.0`): remove, rename or retype a key; change the meaning of existing data; change a hash prefix or algorithm; make previously valid documents invalid.
- **Minor bump** (`2.1`): additive change that default-settings output can contain (a new key, or a new enum value produced by default). The new reader lists both versions in `SUPPORTED_SCHEMA_VERSIONS` and writes the newest.
- **No bump, documented**: a new enum value that is produced only when an opt-in setting is on, and that setting is recorded in `ScanMetadata.settings`. Older readers reject such a document with an error naming the path and the allowed values. The changelog must state the condition.

A test (`test_serialized_enum_values_are_pinned`) pins every serialized enum. Adding a member, such as a new `SourceKind`, makes that test fail on purpose. The failure message points here. The author must make the decision above, record it, and then update the pin.

### Changelog

| Version | Change |
|---|---|
| 2.0 | Initial schema (M1.1). |

Planned and not yet decided: M1.3 is expected to add a `SourceKind` member for parameter origins that only appears in the opt-in recall mode. The decision (bump or conditional no-bump) will be assessed and recorded in that module.

## Compatibility decisions

- The legacy `vulnsight.models.Finding` is unchanged. The detector and the package root still use it. v2 lives in `vulnsight.findings`, and the root export changes when the detector migrates (M1.2).
- Finding v2 offers read-only legacy access: `finding["function"]`, `finding.get(...)` for the nine v1 keys. `function` and `sink` return the sink callee (v1's meaning) or `""` when there is no sink. `severity` returns `"Review required"` while not assessed. `source` returns the origin ids, where v1 stored a constant label. Unknown keys raise `KeyError` from `[]` (v1 raised `AttributeError`) and return the default from `get`.
- `to_dict()` on v2 returns the new schema, not the v1 dictionary.
- The parameter mode is a scan-wide setting and is not stored on findings.

## Not in M1.1

Detector migration, the scan engine, the command-line tool, parameter-mode behavior, computing `structure_hash`, severity calculation, ML verification and explanations are later modules.
