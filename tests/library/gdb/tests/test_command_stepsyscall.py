from __future__ import annotations

import gdb

import pwndbg.aglib.regs
import tests

STEPSYSCALL_X64_BINARY = tests.binaries.get("stepsyscall_x64.out")


def test_command_stepsyscall(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    # Test that the logic correctly handles multiple consecutive jumps
    gdb.execute("stepsyscall")
    address = int(gdb.parse_and_eval("&syscall_write_label"))
    assert pwndbg.aglib.regs.pc == address

    gdb.execute("stepsyscall")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_nextsyscall(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    gdb.execute("nextsyscall")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address
