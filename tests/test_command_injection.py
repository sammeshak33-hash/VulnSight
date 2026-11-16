import pytest

from vulnsight.scanner.command_injection import scan_source


def test_detects_direct_input_to_os_system():
    source = """
import os
os.system(input("Enter command: "))
"""

    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0]["function"] == "os.system"
    assert findings[0]["cwe"] == "CWE-78"


def test_detects_input_variable_to_os_system():
    source = """
import os

command = input("Enter command: ")
os.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_detects_tainted_string_concatenation():
    source = """
import os

filename = input("Enter filename: ")
command = "type " + filename
os.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_detects_tainted_f_string():
    source = """
import os

filename = input("Enter filename: ")
command = f"type {filename}"
os.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_detects_augmented_assignment():
    source = """
import os

command = "type "
command += input("Enter filename: ")
os.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_detects_annotated_assignment():
    source = """
import os

command: str = input("Enter command: ")
os.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_detects_subprocess_with_shell_true():
    source = """
import subprocess

command = input("Enter command: ")
subprocess.run(command, shell=True)
"""

    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0]["function"] == "subprocess.run"


def test_detects_subprocess_check_output_with_shell_true():
    source = """
import subprocess

command = input("Enter command: ")
subprocess.check_output(command, shell=True)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_detects_import_alias():
    source = """
import os as operating_system

command = input("Enter command: ")
operating_system.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_detects_direct_import_alias():
    source = """
from os import system as execute

command = input("Enter command: ")
execute(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_does_not_flag_fixed_command():
    source = """
import os
os.system("dir")
"""

    findings = scan_source(source)

    assert findings == []


def test_does_not_flag_subprocess_without_shell():
    source = """
import subprocess

command = input("Enter command: ")
subprocess.run(command)
"""

    findings = scan_source(source)

    assert findings == []


def test_does_not_flag_tainted_cwd_only():
    source = """
import subprocess

directory = input("Enter directory: ")
subprocess.run("dir", shell=True, cwd=directory)
"""

    findings = scan_source(source)

    assert findings == []


def test_does_not_flag_safe_print():
    source = """
name = input("Enter name: ")
print(name)
"""

    findings = scan_source(source)

    assert findings == []


def test_reassignment_clears_taint():
    source = """
import os

command = input("Enter command: ")
command = "dir"
os.system(command)
"""

    findings = scan_source(source)

    assert findings == []


def test_integer_conversion_is_recognized():
    source = """
import os

value = int(input("Enter number: "))
os.system("echo " + str(value))
"""

    findings = scan_source(source)

    assert findings == []


def test_invalid_python_code():
    source = "if True print('hello')"

    with pytest.raises(ValueError):
        scan_source(source)


def test_finding_contains_standard_fields():
    source = """
import os
os.system(input())
"""

    finding = scan_source(source)[0]

    assert finding.rule_id == "PY-CMD-001"
    assert finding.confidence == "medium"
    assert finding.source == "Untrusted input"
    assert finding.sink == "os.system"
    assert finding.to_dict()["cwe"] == "CWE-78"


def test_taint_does_not_leak_between_functions():
    source = """
import os

def first_function():
    command = input("Enter command: ")

def second_function():
    command = "dir"
    os.system(command)
"""

    findings = scan_source(source)

    assert findings == []


def test_detects_command_injection_inside_function():
    source = """
import os

def execute_command():
    command = input("Enter command: ")
    os.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"


def test_taint_is_preserved_when_one_branch_is_unsafe():
    source = """
import os

if condition:
    command = input("Enter command: ")
else:
    command = "dir"

os.system(command)
"""

    findings = scan_source(source)

    assert len(findings) == 1


def test_taint_is_not_added_when_both_branches_are_safe():
    source = """
import os

if condition:
    command = "dir"
else:
    command = "echo hello"

os.system(command)
"""

    findings = scan_source(source)

    assert findings == []


def test_local_module_reassignment_does_not_use_old_import():
    source = """
import os

def execute():
    os = object()
    os.system(input("Enter command: "))
"""

    findings = scan_source(source)

    assert findings == []


def test_reassigned_imported_function_is_not_detected_as_sink():
    source = """
from os import system as execute

execute = print
execute(input("Enter command: "))
"""

    findings = scan_source(source)

    assert findings == []
