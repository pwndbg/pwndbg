from __future__ import annotations

from collections.abc import Callable

import gdb

import pwndbg.aglib

from . import get_binary

STEPSYSCALL_X64_BINARY = get_binary("stepsyscall.x86-64.out")


def test_command_stepsyscall(start_binary: Callable[[str], None]) -> None:
    start_binary(STEPSYSCALL_X64_BINARY)

    # Test that the logic correctly handles multiple consecutive jumps
    gdb.execute("stepsyscall")
    address = int(gdb.parse_and_eval("&syscall_write_stdout_label"))
    assert pwndbg.aglib.regs.pc == address

    gdb.execute("stepsyscall")
    address = int(gdb.parse_and_eval("&syscall_write_stderr_label"))
    assert pwndbg.aglib.regs.pc == address

    gdb.execute("stepsyscall")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_nextsyscall(start_binary: Callable[[str], None]) -> None:
    start_binary(STEPSYSCALL_X64_BINARY)

    gdb.execute("nextsyscall")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_by_name(start_binary: Callable[[str], None]) -> None:
    """Test stepsyscall with syscall name filter (SYS_exit)"""
    start_binary(STEPSYSCALL_X64_BINARY)

    # Skip all write syscalls, stop at exit
    gdb.execute("stepsyscall SYS_exit")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_by_number(start_binary: Callable[[str], None]) -> None:
    """Test stepsyscall with syscall number filter"""
    start_binary(STEPSYSCALL_X64_BINARY)

    # syscall 60 is exit on x86-64
    gdb.execute("stepsyscall 60")
    address = int(gdb.parse_and_eval("&syscall_exit_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_with_condition(start_binary: Callable[[str], None]) -> None:
    """Test stepsyscall with condition (stop at write to stderr)"""
    start_binary(STEPSYSCALL_X64_BINARY)

    # Stop at write syscall where rdi==2 (stderr)
    gdb.execute("stepsyscall SYS_write $rdi==2")
    address = int(gdb.parse_and_eval("&syscall_write_stderr_label"))
    assert pwndbg.aglib.regs.pc == address


def test_command_stepsyscall_condition_only(start_binary: Callable[[str], None]) -> None:
    """Test stepsyscall with condition only (no syscall filter)"""
    start_binary(STEPSYSCALL_X64_BINARY)

    # Stop at any syscall where rdi==2
    gdb.execute("stepsyscall $rdi==2")
    address = int(gdb.parse_and_eval("&syscall_write_stderr_label"))
    assert pwndbg.aglib.regs.pc == address
