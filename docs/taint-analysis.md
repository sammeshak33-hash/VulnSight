# VulnSight Taint Analysis

## Purpose

The VulnSight taint analysis engine identifies potentially untrusted input and tracks its propagation through Python expressions and control-flow paths.

It helps detect situations where untrusted data reaches security-sensitive operations.

## Main concepts

- **Source:** Where untrusted data enters a program.
- **Propagation:** How untrusted data moves through variables and expressions.
- **Sink:** A function or operation where untrusted data may cause a security issue.
- **Sanitizer:** A recognized transformation that reduces or neutralizes a risk.
- **Taint:** Metadata used to track the origin and propagation of potentially untrusted data.

## Initial sources

The current source policy recognizes:

- `input()`
- `builtins.input()`
- `sys.argv`
- `os.environ`
- `os.getenv()`
- `sys.stdin.read()`
- `sys.stdin.readline()`

## Function parameters

Function parameters are **clean by default**.

A parameter is not automatically considered untrusted simply because it receives a value from outside the function.

For example:

```python
import os


def execute(command):
    os.system(command)
```

This code does not produce a finding solely because `command` is a function parameter.

However, explicit sources inside a function remain detectable:

```python
import os


def execute():
    command = input()
    os.system(command)
```

This produces a potential command-injection finding.

### Limitation

The current engine does not fully track untrusted values passed between function calls.

For example, externally supplied input passed into a function parameter may not be detected if the parameter itself is the only taint origin.

Configurable entry-point policies and interprocedural analysis are future improvements.

## Method-call receivers

A method call returns tainted data when its receiver is tainted and the method is one that returns text derived from the receiver. For example, `x.strip()` is tainted when `x` is tainted, and `os.environ.get("X")` is tainted because `os.environ` is a source.

These methods propagate the receiver's taint:

- `strip`, `lstrip`, `rstrip`, `lower`, `upper`, `casefold`, `title`, `capitalize`, `swapcase`
- `replace`, `format`, `format_map`, `join`, `split`, `rsplit`, `splitlines`, `partition`, `rpartition`
- `expandtabs`, `center`, `ljust`, `rjust`, `zfill`, `translate`, `removeprefix`, `removesuffix`
- `encode`, `decode`

The analysis knows a method's name, not the type of its receiver. Two rules limit the damage when a user-defined class reuses a standard name:

- **Classes in the scanned file.** If a class in the same file defines a method with one of these names (for example `def strip(self)`), that name propagates only from a receiver that is the source value itself, such as `input().strip()` or `x = input(); x.strip()`. A value that has passed through a call, such as `Config(input()).strip()`, is not propagated, because it may be an instance of that class.
- **`get` and `copy`.** These propagate only from a source that the policy declares as a container (`SourceSpec(container=True)`), from an alias of it, or from a `copy()` of it. The default policy declares `os.environ` and `sys.argv`. A source kind such as `NETWORK` or `FRAMEWORK` does not say whether the value is a mapping or a scalar, so the engine does not guess: framework or network sources that are mappings (for example a request object) must be declared. A container that has passed through any other call, including `Config(os.environ).get(...)`, is not propagated.

Limitations of this approach:

- A class that is imported, defined in another file, or inherited from an imported base class is indistinguishable from the built-in type. `Config(input()).strip()` is still reported when `Config` comes from another module. Classes in the scanned file are recognised by their `def` and assignment names in the class body only.
- When a class in the file defines a method with a listed name, chained calls on a derived value stop at that name (for example `input().strip().lower()` when the file defines `lower`).
- `dict(os.environ).get("X")` and `json.loads(input()).get("x")` are not propagated, because the value is no longer the source container.

Other methods do not propagate the receiver's taint. This includes predicates and counters such as `startswith`, `isdigit`, `count` and `find`, methods that read files (`read`, `readline`), `items`, `keys` and `values`, and every user-defined method. Arguments still propagate as before, and sanitizers keep their effect when a receiver method is involved.

## Initial sanitizers

- `int()`
- `float()`
- `bool()`
- `len()`
- `shlex.quote()`

Sanitizer recognition is heuristic and context dependent. A recognized sanitizer does not prove that an expression is safe in every context or on every operating system.

## Initial command injection sinks

- `os.system()`
- `os.popen()`
- `subprocess.call()`
- `subprocess.run()`
- `subprocess.Popen()`
- `subprocess.check_call()`
- `subprocess.check_output()`

Subprocess sinks are considered by this rule only when `shell=True` is explicitly provided.

### The `shell` rule

The rule `PY-CMD-001` (CWE-78) runs on `TaintVisitor` through `vulnsight/scanner/command_injection.py`. The `shell` argument of a subprocess call is read as follows:

| Call | Result | Reported |
|---|---|---|
| `shell=True` (the literal) | applies | yes |
| no `shell` argument | does not apply | no |
| any other constant (`False`, `None`, `0`, `1`) | does not apply | no |
| `shell=<variable or expression>`, or `**options` without an explicit `shell` | unknown | no (see below) |

The legacy detector never reported calls whose `shell` value it could not read. The constant `REPORT_UNKNOWN_SHELL` in `command_injection.py` keeps them suppressed. Setting it to `True` reports them.

Only the command argument counts: the first positional argument, or one of the keywords `args`, `command` and `cmd`. Tainted `cwd` or `env` values do not make a finding.

### Sanitized values

The engine reports a sink whenever tainted data reaches it, including data that a sanitizer neutralized. `vulnsight/scanner/adapter.py` turns each hit into a finding and judges the taint against the platforms `posix` and `windows`:

| Taint effect | Example | Finding |
|---|---|---|
| raw | `os.system(input())` | reported, confidence medium |
| partial | `os.system(shlex.quote(input()))` | reported, confidence low |
| neutralized | `os.system(str(int(input())))` | not reported |

`shlex.quote()` quotes for POSIX shells only. It is not safe escaping for Windows `cmd.exe`, so a flow that is sanitized only by `shlex.quote()` is reported as partially neutralized, with low confidence, and the finding message says so.

### Enclosing function names

Each finding records the scope that runs the sink call, using the engine's own naming:

- Module level is `<module>`.
- A function or class adds its name to its enclosing scope's name, joined with `.`: `f`, `Class.method`, `outer.inner`, `f.Class.method`.
- A lambda is `<lambda@LINE>` and does not take its parent's prefix.
- A statement in a class body gets the class name.
- A decorator, default value, annotation, base class or class keyword runs in the scope that contains the definition.

### Differences from the legacy detector

The legacy detector had its own taint tracking (`scanner/taint.py`, now removed). The fixed corpus in `tests/differential_corpus.py` records its verdicts on 66 snippets and compares them with the new detector. They agree on 62. The four differences are intentional:

| Case | Legacy | Now | Why |
|---|---|---|---|
| A parameter named like an imported module (`def f(os): os.system(...)`) | reported | not reported | Improvement: the parameter shadows the import. |
| Taint assigned in a `try` body | not reported | reported | Improvement: the engine analyzes `try`, `except` and `finally`. |
| `match` statement capturing tainted input | not reported | reported | Improvement: the engine binds `match` captures. |
| `shlex.quote(input())` | not reported | reported, partial, low confidence | Decision: `shlex.quote` is POSIX-specific. |

Other behaviour changes of the migration:

- `scan_source` returns Finding v2 objects. `finding.source` and a string-valued `finding.sink` no longer exist as attributes; use `finding["source"]` (origin ids), `finding["sink"]` (callee) or `finding.sink.callee`.
- Findings are returned in canonical order (file, line, column, rule), not in visit order.
- A finding records the column and end position of the call, and the taint evidence.
- `CommandInjectionVisitor` no longer exists.

## Analysis capabilities

The M0.2 engine includes:

- Variable and expression taint propagation.
- Import aliases and name shadowing.
- Function and nested-function scope handling.
- Global and nonlocal name handling within analyzed function bodies.
- Conservative control-flow merging for branches.
- Loop, exception and context-manager handling.
- Pattern matching support.
- Taint origin and propagation trace tracking.
- CWE- and platform-aware neutralization metadata.

The analysis is primarily intraprocedural. It does not fully model arbitrary interactions between function calls.

## Limitations

The current engine does not fully model:

- Interprocedural data flow and function-call argument propagation.
- External entry-point parameter tainting.
- Complete attribute and container tracking. Reading an attribute of a tainted value (`x.attr`) is not treated as tainted, and `get()` on a container that is not the source itself (for example `json.loads(input()).get("x")`) is not propagated.
- All Python import and dynamic execution patterns.
- Every framework-specific input source.
- All custom sanitizers and security contexts.

## Reporting

Findings represent potential vulnerabilities and require manual review. They use the Finding v2 model described in [finding-schema.md](finding-schema.md).

The scanner does not prove exploitability or guarantee that a program is secure.