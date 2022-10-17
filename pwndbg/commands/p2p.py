import argparse
from typing import List
from typing import Optional

import pwndbg.color
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory

ts = pwndbg.commands.telescope.telescope


class AddrRange:
    def __init__(self, begin, end):
        self.begin = begin
        self.end = end

    def __repr__(self):
        return (self.begin, self.end).__repr__()


def get_addrrange_any_named():
    return [AddrRange(page.start, page.end) for page in pwndbg.gdblib.vmmap.get()]


def guess_numbers_base(num: str):
    base = 10
    if num.startswith("0x"):
        base = 16
    elif num.startswith("0b"):
        base = 2
    elif num.startswith("0"):
        base = 8

    return base


def address_range_explicit(section):
    global parser

    try:
        begin, end = section.split(":")

        begin = int(begin, guess_numbers_base(begin))
        end = int(end, guess_numbers_base(end))

        return AddrRange(begin, end)
    except Exception:
        parser.error(
            '"%s" - Bad format of explicit address range!'
            ' Expected format: "BEGIN_ADDRESS:END_ADDRESS"' % pwndbg.color.red(section)
        )


def address_range(section):
    global parser

    if section == "*" or section == "any":
        return (0, pwndbg.gdblib.arch.ptrmask)

    # User can use syntax: "begin:end" to specify explicit address range instead of named page.
    # TODO: handle page names that contains ':'.
    if ":" in section:
        return [address_range_explicit(section)]

    pages = list(filter(lambda page: section in page.objfile, pwndbg.gdblib.vmmap.get()))

    if pages:
        return [AddrRange(page.start, page.end) for page in pages]
    else:
        parser.error('Memory page with name "%s" does not exist!' % pwndbg.color.red(section))


parser = argparse.ArgumentParser(
    description="Pointer to pointer chain search - "
    "Searches given mapping for all pointers that point to specified mapping (any chain length > 0 is valid)."
    "If only one mapping is given it just looks for any pointers in that mapping."
)

parser.add_argument("mapping_names", type=address_range, nargs="+", help="Mapping name ")


def maybe_points_to_ranges(ptr: int, rs: List[AddrRange]):
    try:
        pointee = pwndbg.gdblib.memory.pvoid(ptr)
    except Exception:
        return None

    for r in rs:
        if pointee >= r.begin and pointee < r.end:
            return pointee

    return None


def p2p_walk(addr, ranges, current_level):
    levels = len(ranges)

    if current_level >= levels:
        return None

    maybe_addr = maybe_points_to_ranges(addr, ranges[current_level])

    if maybe_addr is None:
        return None

    if current_level == levels - 1:
        return addr

    return p2p_walk(maybe_addr, ranges, current_level + 1)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def p2p(mapping_names: Optional[List] = None):

    if not mapping_names:
        return

    if len(mapping_names) == 1:
        mapping_names.append(get_addrrange_any_named())

    for rng in mapping_names[0]:
        for addr in range(rng.begin, rng.end):
            maybe_pointer = p2p_walk(addr, mapping_names, current_level=1)

            if maybe_pointer is not None:
                ts(address=addr, count=1)
