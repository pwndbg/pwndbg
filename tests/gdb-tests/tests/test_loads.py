import os
import re

import tests

from .utils import compile_binary
from .utils import run_gdb_with_script

HELLO = [
    "pwndbg: loaded ### pwndbg commands and ### shell commands. Type pwndbg [--shell | --all] [filter] for a list.",
    "pwndbg: created $rebase, $ida gdb functions (can be used with print/break)",
]

BINARY_SOURCE = tests.binaries.div_zero_binary.get("binary.c")
BINARY = tests.binaries.div_zero_binary.get("binary")
CORE = tests.binaries.div_zero_binary.get("core")


def test_loads_pure_gdb_without_crashing():
    output = run_gdb_with_script().splitlines()
    assert output == HELLO


def test_loads_binary_without_crashing():
    if not os.path.isfile(BINARY):
        compile_binary(BINARY_SOURCE, BINARY)
    output = run_gdb_with_script(binary=BINARY).splitlines()

    for h in HELLO:
        assert h in output
    assert any("Reading symbols from %s..." % BINARY in line for line in output)
    # Old GDB says f"(no debugging symbols found)"
    # New GDB says f"(No debugging symbols found in ${BINARY})"
    assert any("(no debugging symbols found" in line.lower() for line in output)


def test_loads_binary_with_core_without_crashing():
    if not os.path.isfile(BINARY):
        compile_binary(BINARY_SOURCE, BINARY)
    if not os.path.isfile(CORE):
        create_coredump = ["run", f"generate-core-file {CORE}"]
        run_gdb_with_script(binary=BINARY, pyafter=create_coredump)
        assert os.path.isfile(CORE)
    output = run_gdb_with_script(binary=BINARY, core=CORE).splitlines()

    assert any("Reading symbols from %s..." % BINARY in line for line in output)
    # Old GDB says f"(no debugging symbols found)"
    # New GDB says f"(No debugging symbols found in ${BINARY})"
    assert any("(no debugging symbols found" in line.lower() for line in output)
    assert "Program terminated with signal SIGFPE, Arithmetic exception." in output
    for h in HELLO:
        assert h in output


    lwp_line = re.compile(r"^\[New LWP \d+\]$")
    assert any([lwp_line.match(line) for line in output])

    binary_line = re.compile("^Core was generated by .+$")
    assert any([binary_line.match(line) for line in output])

    crash_address_line = re.compile(r"^#0  0x[0-9a-fA-F]+ in main \(\)$")
    assert any([crash_address_line.match(line) for line in output])


def test_loads_core_without_crashing():
    if not os.path.isfile(BINARY):
        compile_binary(BINARY_SOURCE, BINARY)
    if not os.path.isfile(CORE):
        create_coredump = ["run", f"generate-core-file {CORE}"]
        run_gdb_with_script(binary=BINARY, pyafter=create_coredump)
        assert os.path.isfile(CORE)
    output = run_gdb_with_script(core=CORE).splitlines()

    expected = [
        "Program terminated with signal SIGFPE, Arithmetic exception.",
    ]
    expected += HELLO

    assert all(item in output for item in expected)

    lwp_line = re.compile(r"^\[New LWP \d+\]$")
    assert any([lwp_line.match(line) for line in output])

    binary_line = re.compile("^Core was generated by .+$")
    assert any([binary_line.match(line) for line in output])

    crash_address_line = re.compile(r"^#0  0x[0-9a-fA-F]+ in \?\? \(\)$")
    assert any([crash_address_line.match(line) for line in output])


def test_entry_no_file_loaded():
    # This test is just to demonstrate that if gdb fails, all we have left is its stdout/err
    output = run_gdb_with_script(binary="not_existing_binary", pyafter="entry").splitlines()

    expected = ["not_existing_binary: No such file or directory."]
    expected += HELLO
    expected += ["entry: There is no file loaded."]

    assert all(item in output for item in expected)
