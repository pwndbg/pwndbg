from __future__ import annotations

import gdb
import pytest

import pwndbg.aglib.regs
import tests

CONDBR_X64_BINARY = tests.binaries.get("conditional_branch_breakpoints_x64.out")


@pytest.mark.parametrize("binary", [CONDBR_X64_BINARY], ids=["x86-64"])
def test_command_break_if_x64(start_binary, binary):
    """
    Tests the chain for a non-nested linked list
    """

    start_binary(binary)
    gdb.execute("break break_here")
    gdb.execute("run")

    gdb.execute("break break_here0")
    gdb.execute("break break_here1")
    gdb.execute("break-if-taken branch0")
    gdb.execute("break-if-taken branch1")
    gdb.execute("break-if-not-taken branch2")
    gdb.execute("break-if-not-taken branch3")

    continue_and_test_pc("branch0")
    continue_and_test_pc("break_here0")
    continue_and_test_pc("break_here1")
    continue_and_test_pc("branch3")


def continue_and_test_pc(stop_label):
    gdb.execute("continue")
    address = int(gdb.parse_and_eval(f"&{stop_label}"))
    assert pwndbg.aglib.regs.pc == address
