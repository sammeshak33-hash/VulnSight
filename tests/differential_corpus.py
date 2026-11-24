"""Fixed differential corpus: legacy detector verdicts versus the new detector.

Each case holds a source snippet, the verdict of the legacy detector and the
verdict of the new detector. The legacy verdict was captured once, before the
legacy detector was replaced, as sorted ``(line, callee)`` pairs. The new
verdict is ``(line, callee, taint_effect, confidence)``. ``difference``
explains every case where the two disagree and is empty where they agree.

The legacy verdicts are data, not code: the legacy detector no longer exists
in the repository. Do not regenerate them from the new detector.
"""

from typing import NamedTuple


class Case(NamedTuple):
    name: str
    source: str
    old: tuple
    new: tuple
    difference: str


def src(*lines):
    return "\n".join(lines)


CASES = (
    Case(
        name="method_on_tainted",
        source=src("import os", "x = input()", "os.system(x.strip())"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="method_chain_src",
        source=src("import os", "os.system(input().strip())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="environ_get",
        source=src("import os", "os.system(os.environ.get('X'))"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="environ_sub",
        source=src("import os", "os.system(os.environ['X'])"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="getenv",
        source=src("import os", "os.system(os.getenv('X'))"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="argv_sub",
        source=src("import os, sys", "os.system(sys.argv[1])"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="argv_slice_join",
        source=src("import os, sys", "os.system(' '.join(sys.argv[1:]))"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="str_format",
        source=src("import os", "x=input()", "os.system('ls {}'.format(x))"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="percent",
        source=src("import os", "x=input()", "os.system('ls %s' % x)"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="unknown_call_taint",
        source=src("import os", "x=input()", "os.system(foo(x))"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="user_func_ret",
        source=src("import os", "def f(a):", "    return a", "os.system(f(input()))"),
        old=((4, "os.system"),),
        new=((4, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="shell_true",
        source=src("import subprocess", "subprocess.run(input(), shell=True)"),
        old=((2, "subprocess.run"),),
        new=((2, "subprocess.run", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="shell_false",
        source=src("import subprocess", "subprocess.run(input(), shell=False)"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="shell_absent",
        source=src("import subprocess", "subprocess.run(input())"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="shell_var",
        source=src(
            "import subprocess", "flag=True", "subprocess.run(input(), shell=flag)"
        ),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="shell_one",
        source=src("import subprocess", "subprocess.run(input(), shell=1)"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="shell_kwargs",
        source=src("import subprocess", "opts={}", "subprocess.run(input(), **opts)"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="shell_none",
        source=src("import subprocess", "subprocess.run(input(), shell=None)"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="list_arg",
        source=src("import subprocess", "subprocess.run(['ls', input()], shell=True)"),
        old=((2, "subprocess.run"),),
        new=((2, "subprocess.run", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="starred",
        source=src("import os", "os.system(*[input()])"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="kw_args",
        source=src("import subprocess", "subprocess.run(args=input(), shell=True)"),
        old=((2, "subprocess.run"),),
        new=((2, "subprocess.run", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="kw_cmd_os",
        source=src("import os", "os.system(command=input())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="loop_carried",
        source=src(
            "import os",
            "x=''",
            "for i in range(2):",
            "    os.system(x)",
            "    x=input()",
        ),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="loop_body",
        source=src(
            "import os", "for i in range(2):", "    x=input()", "    os.system(x)"
        ),
        old=((4, "os.system"),),
        new=((4, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="while_body",
        source=src("import os", "while True:", "    x=input()", "    os.system(x)"),
        old=((4, "os.system"),),
        new=((4, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="try_body",
        source=src(
            "import os",
            "try:",
            "    x=input()",
            "except Exception:",
            "    x=''",
            "os.system(x)",
        ),
        old=(),
        new=((6, "os.system", "raw", "medium"),),
        difference=(
            "Improvement. The engine analyzes try, except and finally blocks and "
            "joins their taint states. The legacy detector had no try handling and "
            "missed taint assigned in a try body."
        ),
    ),
    Case(
        name="with_body",
        source=src(
            "import os", "with open('f') as fh:", "    x=input()", "    os.system(x)"
        ),
        old=((4, "os.system"),),
        new=((4, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="with_as_tainted",
        source=src(
            "import os", "with open(input()) as fh:", "    os.system(fh.read())"
        ),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="fn_param",
        source=src("import os", "def f(c):", "    os.system(c)"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="fn_closure_global",
        source=src("import os", "x=input()", "def f():", "    os.system(x)"),
        old=((4, "os.system"),),
        new=((4, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="fn_closure_late",
        source=src("import os", "def f():", "    os.system(x)", "x=input()"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="nested_fn",
        source=src(
            "import os",
            "def a():",
            "    x=input()",
            "    def b():",
            "        os.system(x)",
            "    b()",
        ),
        old=((5, "os.system"),),
        new=((5, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="method",
        source=src(
            "import os", "class C:", "    def m(self):", "        os.system(input())"
        ),
        old=((4, "os.system"),),
        new=((4, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="lambda",
        source=src("import os", "f = lambda: os.system(input())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="comprehension",
        source=src("import os", "os.system(''.join([c for c in input()]))"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="walrus",
        source=src("import os", "if (x:=input()):", "    os.system(x)"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="tuple_unpack",
        source=src("import os", "a,b=input(),'x'", "os.system(a)"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="tuple_unpack_clean_second",
        source=src("import os", "a,b=input(),'x'", "os.system(b)"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="dict_value",
        source=src("import os", "d={'k':input()}", "os.system(d['k'])"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="attr_on_obj",
        source=src(
            "import os", "class O: pass", "o=O()", "o.v=input()", "os.system(o.v)"
        ),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="int_san",
        source=src("import os", "os.system('echo ' + str(int(input())))"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="shlex_quote",
        source=src("import os, shlex", "os.system('echo ' + shlex.quote(input()))"),
        old=(),
        new=((2, "os.system", "partial", "low"),),
        difference=(
            "Decision D2. shlex.quote neutralizes CWE-78 on POSIX only. The legacy "
            "detector treated the quoted value as clean. The new detector reports "
            "it with taint_effect partial and low confidence, because the value is "
            "not safely escaped for Windows cmd.exe."
        ),
    ),
    Case(
        name="len_san",
        source=src("import os", "os.system('x'*len(input()))"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="if_else_one_tainted",
        source=src(
            "import os",
            "if cond:",
            "    x=input()",
            "else:",
            "    x='a'",
            "os.system(x)",
        ),
        old=((6, "os.system"),),
        new=((6, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="reassign_clear",
        source=src("import os", "x=input()", "x='ls'", "os.system(x)"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="import_alias",
        source=src("import os as o", "o.system(input())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="from_alias",
        source=src("from os import system as s", "s(input())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="shadow_param",
        source=src("import os", "def f(os):", "    os.system(input())"),
        old=((3, "os.system"),),
        new=(),
        difference=(
            "Improvement. A parameter named like an imported module shadows the "
            "import. The legacy detector kept resolving the name through the import "
            "and reported a false positive."
        ),
    ),
    Case(
        name="shadow_local",
        source=src("import os", "os = object()", "os.system(input())"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="popen",
        source=src("import os", "os.popen(input())"),
        old=((2, "os.popen"),),
        new=((2, "os.popen", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="subprocess_popen_shell",
        source=src("import subprocess", "subprocess.Popen(input(), shell=True)"),
        old=((2, "subprocess.Popen"),),
        new=((2, "subprocess.Popen", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="from_subprocess",
        source=src("from subprocess import run", "run(input(), shell=True)"),
        old=((2, "subprocess.run"),),
        new=((2, "subprocess.run", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="stdin_read",
        source=src("import os, sys", "os.system(sys.stdin.read())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="stdin_readline",
        source=src("import os, sys", "os.system(sys.stdin.readline())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="builtins_input",
        source=src("import os, builtins", "os.system(builtins.input())"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="os_environ_attr_copy",
        source=src("import os", "env=os.environ", "os.system(env['X'])"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="fstring",
        source=src("import os", "x=input()", "os.system(f'ls {x}')"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="augassign",
        source=src("import os", "x='a'", "x+=input()", "os.system(x)"),
        old=((4, "os.system"),),
        new=((4, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="annassign",
        source=src("import os", "x:str=input()", "os.system(x)"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="return_taint_local_call",
        source=src("import os", "def g():", "    return input()", "os.system(g())"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="async_fn",
        source=src("import os", "async def f():", "    os.system(input())"),
        old=((3, "os.system"),),
        new=((3, "os.system", "raw", "medium"),),
        difference="",
    ),
    Case(
        name="decorator_default",
        source=src("import os", "def f(a=input()):", "    os.system(a)"),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="match_stmt",
        source=src(
            "import os", "match input():", "    case x:", "        os.system(x)"
        ),
        old=(),
        new=((4, "os.system", "raw", "medium"),),
        difference=(
            "Improvement. The engine binds match-case captures from the subject's "
            "taint. The legacy detector had no match handling."
        ),
    ),
    Case(
        name="global_decl",
        source=src(
            "import os",
            "def f():",
            "    global y",
            "    y=input()",
            "f()",
            "os.system(y)",
        ),
        old=(),
        new=(),
        difference="",
    ),
    Case(
        name="two_sinks_same_line",
        source=src("import os", "os.system(input()); os.system(input())"),
        old=((2, "os.system"), (2, "os.system")),
        new=((2, "os.system", "raw", "medium"), (2, "os.system", "raw", "medium")),
        difference="",
    ),
    Case(
        name="multiline_call",
        source=src("import os", "os.system(", "  input()", ")"),
        old=((2, "os.system"),),
        new=((2, "os.system", "raw", "medium"),),
        difference="",
    ),
)
