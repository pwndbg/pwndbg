from __future__ import annotations

import argparse
from typing import List
from typing import Tuple

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.vmmap
import pwndbg.color
import pwndbg.commands
import pwndbg.commands.telescope
from pwndbg.commands import CommandCategory

ts = pwndbg.commands.telescope.telescope


class AddrRange:
    def __init__(self, begin: int, end: int) -> None:
        self.begin = begin
        self.end = end

    def __repr__(self) -> str:
        return (self.begin, self.end).__repr__()


def get_addrrange_any_named() -> List[AddrRange]:
    return [AddrRange(page.start, page.end) for page in pwndbg.aglib.vmmap.get()]


def address_range_explicit(section: str) -> AddrRange:
    try:
        begin, end = section.split(":")

        return AddrRange(int(begin, 0), int(end, 0))
    except Exception:
        parser.error(
            '"%s" - Bad format of explicit address range!'
            ' Expected format: "BEGIN_ADDRESS:END_ADDRESS"' % pwndbg.color.red(section)
        )


def address_range(section: str) -> List[AddrRange] | Tuple[int, int] | None:
    if section in ("*", "any"):
        return (0, pwndbg.aglib.arch.ptrmask)

    # User can use syntax: "begin:end" to specify explicit address range instead of named page.
    # TODO: handle page names that contains ':'.
    if ":" in section:
        return [address_range_explicit(section)]

    pages = list(filter(lambda page: section in page.objfile, pwndbg.aglib.vmmap.get()))

    if pages:
        return [AddrRange(page.start, page.end) for page in pages]
    else:
        parser.error(f'Memory page with name "{pwndbg.color.red(section)}" does not exist!')


parser = argparse.ArgumentParser(
    description="""Pointer to pointer chain search. Searches given mapping for all pointers that point to specified mapping.

Any chain length greater than 0 is valid. If only one mapping is given it just looks for any pointers in that mapping.""",
)

parser.add_argument("mapping_names", type=address_range, nargs="+", help="Mapping name ")


def maybe_points_to_ranges(ptr: int, rs: List[AddrRange]):
    try:
        pointee = pwndbg.aglib.memory.pvoid(ptr)
    except Exception:
        return None

    for r in rs:
        if r.begin <= pointee < r.end:
            return pointee

    return None


def p2p_walk(addr: int, ranges: List[List[AddrRange]], current_level: int) -> int | None:
    levels = len(ranges)

    if current_level >= levels:
        return None

    maybe_addr = maybe_points_to_ranges(addr, ranges[current_level])

    if maybe_addr is None:
        return None

    if current_level == levels - 1:
        return addr

    return p2p_walk(maybe_addr, ranges, current_level + 1)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def p2p(mapping_names: List[List[AddrRange]] | None = None) -> None:
    if not mapping_names:
        return

    if len(mapping_names) == 1:
        mapping_names.append(get_addrrange_any_named())

    for rng in mapping_names[0]:
        for addr in range(rng.begin, rng.end):
            maybe_pointer = p2p_walk(addr, mapping_names, current_level=1)

            if maybe_pointer is not None:
                ts(address=addr, count=1)
