from __future__ import annotations

import gdb

import pwndbg.aglib

from . import get_binary

STEPSYSCALL_X64_BINARY = get_binary("stepsyscall.x86-64.out")


def test_command_stepsyscall(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    # Test that the logic correctly handles multiple consecutive jumps
    gdb.execute("stepsyscall")
    address = int(gdb.parse_and_eval("&syscall_write_label"))
    assert pwndbg.aglib.regs.pc == address

    gdb.execute("stepsyscall")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_with_number(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    # Stop at exit (60)
    gdb.execute("stepsyscall 60")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_with_name(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    # Stop at write
    gdb.execute("stepsyscall write")
    address = int(gdb.parse_and_eval("&syscall_write_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_with_expression(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    # Stop at rax == 60
    gdb.execute("stepsyscall $rax == 60")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_with_name_and_condition(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    # Stop at write when rdi is 1
    gdb.execute("stepsyscall write $rdi == 1")
    address = int(gdb.parse_and_eval("&syscall_write_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_nextsyscall(start_binary):
    start_binary(STEPSYSCALL_X64_BINARY)

    gdb.execute("nextsyscall")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address
