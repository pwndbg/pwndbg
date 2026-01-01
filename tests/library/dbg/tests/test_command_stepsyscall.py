from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

STEPSYSCALL_X64_BINARY = get_binary("stepsyscall.x86-64.out")


@pwndbg_test
async def test_command_stepsyscall(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # Test that the logic correctly handles multiple consecutive jumps
    await ctrl.execute("stepsyscall")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_write_stdout_label")
    assert pwndbg.aglib.regs.pc == address

    await ctrl.execute("stepsyscall")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_write_stderr_label")
    assert pwndbg.aglib.regs.pc == address

    await ctrl.execute("stepsyscall")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_exit_label")
    assert pwndbg.aglib.regs.pc == address


@pwndbg_test
async def test_command_nextsyscall(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    await ctrl.execute("nextsyscall")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_exit_label")
    assert pwndbg.aglib.regs.pc == address


@pwndbg_test
async def test_command_stepsyscall_by_name(ctrl: Controller) -> None:
    """Test stepsyscall with syscall name filter (SYS_exit)"""
    import pwndbg.aglib
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # Skip all write syscalls, stop at exit
    await ctrl.execute("stepsyscall SYS_exit")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_exit_label")
    assert pwndbg.aglib.regs.pc == address


@pwndbg_test
async def test_command_stepsyscall_by_number(ctrl: Controller) -> None:
    """Test stepsyscall with syscall number filter"""
    import pwndbg.aglib
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # syscall 60 is exit on x86-64
    await ctrl.execute("stepsyscall 60")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_exit_label")
    assert pwndbg.aglib.regs.pc == address


@pwndbg_test
async def test_command_stepsyscall_with_condition(ctrl: Controller) -> None:
    """Test stepsyscall with condition (stop at write to stderr)"""
    import pwndbg.aglib
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # Stop at write syscall where rdi==2 (stderr)
    await ctrl.execute("stepsyscall SYS_write $rdi==2")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_write_stderr_label")
    assert pwndbg.aglib.regs.pc == address


@pwndbg_test
async def test_command_stepsyscall_condition_only(ctrl: Controller) -> None:
    """Test stepsyscall with condition only (no syscall filter)"""
    import pwndbg.aglib
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # Stop at any syscall where rdi==2
    await ctrl.execute("stepsyscall $rdi==2")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_write_stderr_label")
    assert pwndbg.aglib.regs.pc == address
