from __future__ import annotations

import gdb
import pytest

import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")
CRASH_SIMPLE_BINARY = tests.binaries.get("crash_simple.out.hardcoded")


def test_command_nextproginstr_binary_not_running():
    out = gdb.execute("nextproginstr", to_string=True)
    assert out == "nextproginstr: The program is not being run.\n"


def test_command_nextproginstr(start_binary):
    start_binary(REFERENCE_BINARY)

    gdb.execute("break main")
    gdb.execute("continue")

    out = gdb.execute("nextproginstr", to_string=True)
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"

    # Sanity check
    exec_bin_pages = [
        p for p in pwndbg.aglib.vmmap.get() if p.objfile == pwndbg.aglib.proc.exe and p.execute
    ]
    assert any(pwndbg.aglib.regs.pc in p for p in exec_bin_pages)
    main_page = pwndbg.aglib.vmmap.find(pwndbg.aglib.regs.pc)

    gdb.execute("break puts")
    gdb.execute("continue")

    # Sanity check that we are in libc
    assert "libc" in pwndbg.aglib.vmmap.find(pwndbg.aglib.regs.rip).objfile

    # Execute nextproginstr and see if we came back to the same vmmap page
    gdb.execute("nextproginstr")
    assert pwndbg.aglib.regs.pc in main_page

    # Ensure that nextproginstr won't jump now
    out = gdb.execute("nextproginstr", to_string=True)
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"


@pytest.mark.parametrize(
    "command",
    ("nextcall", "nextjump", "nextproginstr", "nextret", "nextsyscall", "stepret", "stepsyscall"),
)
def test_next_command_doesnt_freeze_crashed_binary(start_binary, command):
    start_binary(REFERENCE_BINARY)

    # The nextproginstr won't step if we are already on the binary address
    # and interestingly, other commands won't step if the address can't be disassemblied
    if command == "nextproginstr":
        pwndbg.aglib.regs.pc = 0x1234

    # This should not halt/freeze the program
    gdb.execute(command, to_string=True)
