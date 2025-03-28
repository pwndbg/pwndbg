from __future__ import annotations

from dataclasses import dataclass

import pwndbg.aglib.memory


@dataclass
class SavedContext:
    frame_layout: list[tuple[int, str]]
    offsets: dict[str, int]

    def read_saved_register(self, reg: str, sp: int = None) -> int | None:
        if sp is None:
            sp = pwndbg.aglib.regs.sp

        ptr_size = pwndbg.aglib.arch.ptrsize

        address = sp + self.offsets[reg]

        try:
            mem = pwndbg.aglib.memory.read(address, ptr_size)
        except pwndbg.dbg_mod.Error:
            return None

        value = pwndbg.aglib.arch.unpack(mem)

        return value


def create_saved_context_handler(values: dict[str, int]):
    items = list(values.items())

    return SavedContext(
        sorted([(y, x) for (x, y) in items]),
        values,
    )


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


ARM_CORTEX_M_EXCEPTION_STACK = create_saved_context_handler(
    ARM_CORTEX_M_EXCEPTION_STACK_FRAME_OFFSETS
)
