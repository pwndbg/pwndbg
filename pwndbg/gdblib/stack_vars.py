"""
Looking up stack variable names by their addresses.
"""

from __future__ import annotations

import gdb

import pwndbg.lib.cache


def _get_frame_pc() -> int | None:
    try:
        frame = gdb.selected_frame()
    except (gdb.error, RuntimeError):
        return None

    if not frame:
        return None

    return int(frame.pc())


@pwndbg.lib.cache.cache_until("stop", "start")
def _get_current_frame_vars(frame_pc: int) -> tuple[tuple[int, int, str], ...]:
    try:
        frame = gdb.selected_frame()
    except (gdb.error, RuntimeError):
        return ()

    if not frame:
        return ()

    try:
        block = frame.block()
    except (gdb.error, RuntimeError):
        return ()

    if not block:
        return ()

    variables = []
    while block:
        for sym in block:
            if not (sym.is_variable or sym.is_argument):
                continue

            try:
                value = sym.value(frame)
                addr = int(value.address)
                size = value.type.sizeof
                variables.append((addr, addr + size, sym.name))
            except (gdb.error, AttributeError, TypeError):
                continue

        block = block.superblock

    return tuple(variables)


def get_stack_var_name(address: int) -> str | None:
    """
    Return the name of the stack variable covering the address.

    Includes offset notation like "buf+0x8" if not at variable start.
    """
    frame_pc = _get_frame_pc()
    if frame_pc is None:
        return None

    variables = _get_current_frame_vars(frame_pc)

    for start, end, name in variables:
        if start <= address < end:
            offset = address - start
            return name if offset == 0 else f"{name}+{offset:#x}"

    return None
