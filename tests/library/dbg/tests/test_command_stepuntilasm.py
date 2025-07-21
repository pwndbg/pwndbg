from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

STEPUNTILASM_X64_BINARY = get_binary("stepuntilasm_x64.out")


@pwndbg_test
async def test_command_untilasm_x64(ctrl: Controller) -> None:
    await launch_to(ctrl, STEPUNTILASM_X64_BINARY, "break_here")

    await run_and_verify(ctrl, "stop1", "nop")
    await run_and_verify(ctrl, "stop2", "xor rax, rax")
    await run_and_verify(ctrl, "stop3", "mov qword ptr [rax], 0x20")
    await run_and_verify(ctrl, "stop4", "mov dword ptr [rax+4], 0x20")


async def run_and_verify(ctrl: Controller, stop_label: str, asm: str) -> None:
    import pwndbg.aglib.regs
    import pwndbg.aglib.symbol

    await ctrl.execute(f"stepuntilasm {asm}")
    address = pwndbg.aglib.symbol.lookup_symbol_addr(stop_label)
    assert pwndbg.aglib.regs.pc == address
