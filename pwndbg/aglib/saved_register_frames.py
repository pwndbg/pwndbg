from __future__ import annotations

from dataclasses import dataclass

import pwndbg.aglib.memory


@dataclass
class SavedRegisterFrame:
    """
    A list of registers that have been saved to process memory for later restoration.

    For example, on syscall entry, the process registers are saved to the kernel stack.
    """

    # List of (offset, register name), sorted from smallest to largest offset
    frame_layout: list[tuple[int, str]]
    offsets: dict[str, int]

    def __init__(self, register_offsets: dict[str, int]):
        self.offsets = register_offsets

        self.frame_layout = sorted(((y, x) for (x, y) in register_offsets.items()))

    def read_saved_register(self, reg: str, sp: int = None) -> int | None:
        if sp is None:
            sp = pwndbg.aglib.regs.sp

        try:
            mem = pwndbg.aglib.memory.read(sp + self.offsets[reg], pwndbg.aglib.arch.ptrsize)
        except pwndbg.dbg_mod.Error:
            return None

        return pwndbg.aglib.arch.unpack(mem)


# Basic exception stack frame defined here - https://developer.arm.com/documentation/107706/0100/Exceptions-and-interrupts-overview/Stack-frames
ARM_CORTEX_M_EXCEPTION_STACK_FRAME_OFFSETS = {
    "r0": 0x0,
    "r1": 0x4,
    "r2": 0x8,
    "r3": 0xC,
    "r12": 0x10,
    "lr": 0x14,
    "pc": 0x18,
    "xpsr": 0x1C,
}


ARM_CORTEX_M_EXCEPTION_STACK = SavedRegisterFrame(ARM_CORTEX_M_EXCEPTION_STACK_FRAME_OFFSETS)
