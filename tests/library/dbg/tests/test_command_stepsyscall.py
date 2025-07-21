from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

STEPSYSCALL_X64_BINARY = get_binary("stepsyscall_x64.out")


@pwndbg_test
async def test_command_stepsyscall(ctrl: Controller) -> None:
    import pwndbg.aglib.regs
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    # Test that the logic correctly handles multiple consecutive jumps
    await ctrl.execute("stepsyscall")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_write_label")
    assert pwndbg.aglib.regs.pc == address

    await ctrl.execute("stepsyscall")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_exit_label")
    assert pwndbg.aglib.regs.pc == address


@pwndbg_test
async def test_command_nextsyscall(ctrl: Controller) -> None:
    import pwndbg.aglib.regs
    import pwndbg.aglib.symbol

    await ctrl.launch(STEPSYSCALL_X64_BINARY)

    await ctrl.execute("nextsyscall")
    address = pwndbg.aglib.symbol.lookup_symbol_addr("syscall_exit_label")
    assert pwndbg.aglib.regs.pc == address
