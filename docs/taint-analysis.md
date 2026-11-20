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
- Complete attribute and container tracking.
- All Python import and dynamic execution patterns.
- Every framework-specific input source.
- All custom sanitizers and security contexts.

## Reporting

Findings represent potential vulnerabilities and require manual review.

The scanner does not prove exploitability or guarantee that a program is secure.