# VulnSight Taint Analysis

## Purpose

The taint analysis engine identifies potentially untrusted input
and tracks its propagation through Python expressions.

## Main concepts

- Source: where untrusted data enters a program.
- Propagation: how untrusted data moves through variables and expressions.
- Sink: a function or operation where untrusted data may cause a security issue.
- Sanitizer: a recognized transformation that reduces or neutralizes a risk.

## Initial sources

- input()
- builtins.input()
- sys.argv
- os.environ
- os.getenv()
- sys.stdin.read()
- sys.stdin.readline()

## Initial sanitizers

- int()
- float()
- bool()
- len()
- shlex.quote()

Sanitizer recognition is heuristic and context dependent.
It does not prove that an expression is safe in every context.

## Initial command injection sinks

- os.system()
- os.popen()
- subprocess.call()
- subprocess.run()
- subprocess.Popen()
- subprocess.check_call()
- subprocess.check_output()

Subprocess sinks are considered by this rule only when shell=True
is explicitly provided.

## Limitations

The initial engine does not fully model:

- Interprocedural data flow.
- Complex control-flow branches.
- Loops and exception paths.
- Custom sanitizers.
- Complete container tracking.
- All Python import and dynamic execution patterns.

## Reporting

Findings are potential vulnerabilities requiring manual review.
The scanner does not prove exploitability or program security.