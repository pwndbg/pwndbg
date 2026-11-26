from __future__ import annotations

import argparse

import pwndbg.aglib
import pwndbg.aglib.memory
import pwndbg.commands
import pwndbg.commands.telescope
from pwndbg.commands import AddrRange
from pwndbg.commands import CommandCategory

ts = pwndbg.commands.telescope.telescope

parser = argparse.ArgumentParser(
    description="""Pointer to pointer chain search. Searches given mapping for all pointers that point to specified mapping.

Any chain length greater than 0 is valid. If only one mapping is given it just looks for any pointers in that mapping.""",
)

parser.add_argument(
    "mapping_names",
    type=pwndbg.commands.parse_address_range,
    nargs="+",
    help='Mapping name (as shown in vmmap), an explicit "begin:end" address range, or "any"/"*" for all mappings.',
)


def maybe_points_to_ranges(ptr: int, rs: list[AddrRange]):
    try:
        pointee = pwndbg.aglib.memory.read_pointer_width(ptr)
    except Exception:
        return None

    for r in rs:
        if r.begin <= pointee < r.end:
            return pointee

    return None


def p2p_walk(addr: int, ranges: list[list[AddrRange]], current_level: int) -> int | None:
    levels = len(ranges)

    if current_level >= levels:
        return None

    maybe_addr = maybe_points_to_ranges(addr, ranges[current_level])

    if maybe_addr is None:
        return None

    if current_level == levels - 1:
        return addr

    return p2p_walk(maybe_addr, ranges, current_level + 1)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MEMORY,
    examples="""
>p2p stack libc
    Find pointers on the stack that point into libc.
>p2p stack any
    Find pointers on the stack that point into any mapping.
>p2p libc stack
    Find pointers in libc that point to the stack.
>p2p 0x7ffe0000:0x7ffe1000 any
    Find pointers in an explicit address range that point into any mapping.
""",
)
@pwndbg.commands.OnlyWhenRunning
def p2p(mapping_names: list[list[AddrRange]] | None = None) -> None:
    if not mapping_names:
        return

    if len(mapping_names) == 1:
        mapping_names.append(pwndbg.commands.all_address_ranges())

    for rng in mapping_names[0]:
        for addr in range(rng.begin, rng.end):
            maybe_pointer = p2p_walk(addr, mapping_names, current_level=1)

            if maybe_pointer is not None:
                ts(address=addr, count=1)
