"""
Prints out pointer chains starting at some address in memory.

Generally used to print out the stack or register values.
"""

from __future__ import annotations

import argparse
import collections
import math
from typing import DefaultDict
from typing import Dict
from typing import List

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.color.telescope as T
import pwndbg.commands
from pwndbg.color import theme
from pwndbg.commands import CommandCategory

telescope_lines = pwndbg.config.add_param(
    "telescope-lines", 8, "number of lines to printed by the telescope command"
)
skip_repeating_values = pwndbg.config.add_param(
    "telescope-skip-repeating-val",
    True,
    "whether to skip repeating values of the telescope command",
)
skip_repeating_values_minimum = pwndbg.config.add_param(
    "telescope-skip-repeating-val-min",
    3,
    "minimum amount of repeated values before skipping lines",
)
print_framepointer_offset = pwndbg.config.add_param(
    "telescope-framepointer-offset",
    True,
    "print offset to framepointer for each address, if sufficiently small",
)
print_retaddr_in_frame = pwndbg.config.add_param(
    "telescope-frame-print-retaddr", True, "print one pointer past the stack frame"
)
dont_skip_registers = pwndbg.config.add_param(
    "telescope-dont-skip-registers", True, "don't skip a repeated line if a registers points to it"
)

offset_separator = theme.add_param(
    "telescope-offset-separator", "│", "offset separator of the telescope command"
)
offset_delimiter = theme.add_param(
    "telescope-offset-delimiter", ":", "offset delimiter of the telescope command"
)
repeating_marker = theme.add_param(
    "telescope-repeating-marker", "... ↓", "repeating values marker of the telescope command"
)


parser = argparse.ArgumentParser(
    description="Recursively dereferences pointers starting at the specified address."
)
parser.add_argument(
    "-r",
    "--reverse",
    dest="reverse",
    action="store_true",
    default=False,
    help="Show <count> previous addresses instead of next ones",
)

parser.add_argument(
    "-f",
    "--frame",
    dest="frame",
    action="store_true",
    default=False,
    help="Show the stack frame, from rsp to rbp",
)

parser.add_argument(
    "-i",
    "--inverse",
    dest="inverse",
    action="store_true",
    default=False,
    help="Show the stack reverse growth",
)


parser.add_argument(
    "address", nargs="?", default="$sp", type=int, help="The address to telescope at."
)

parser.add_argument(
    "count", nargs="?", default=telescope_lines, type=int, help="The number of lines to show."
)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def telescope(
    address=None, count=telescope_lines, to_string=False, reverse=False, frame=False, inverse=False
):
    """
    Recursively dereferences pointers starting at the specified address
    ($sp by default)
    """
    ptrsize = pwndbg.aglib.typeinfo.ptrsize
    if telescope.repeat:
        address = telescope.last_address + ptrsize
        telescope.offset += 1
    else:
        telescope.offset = 0

    address = address if address else pwndbg.aglib.regs.sp
    if address is None:
        print("Cannot display stack frame because stack pointer is unavailable")
        return

    address = int(address) & pwndbg.aglib.arch.ptrmask
    input_address = address
    count = max(int(count), 1) & pwndbg.aglib.arch.ptrmask
    delimiter = T.delimiter(offset_delimiter)
    separator = T.separator(offset_separator)

    # Allow invocation of "telescope 20" to dump 20 bytes at the stack pointer
    if address < pwndbg.aglib.memory.MMAP_MIN_ADDR and not pwndbg.aglib.memory.peek(address):
        count = address
        address = pwndbg.aglib.regs.sp

    # Allow invocation of telescope -r to dump previous addresses
    if reverse:
        address -= (count - 1) * ptrsize

    # Allow invocation of telescope -f (--frame) to dump all addresses in a frame
    if frame:
        sp = pwndbg.aglib.regs.sp
        bp = pwndbg.aglib.regs[pwndbg.aglib.regs.frame]
        if sp > bp:
            print("Cannot display stack frame because base pointer is below stack pointer")
            return

        for page in pwndbg.aglib.vmmap.get():
            if sp in page and bp not in page:
                print(
                    "Cannot display stack frame because base pointer is not on the same page with stack pointer"
                )
                return

        address = sp
        count = int((bp - sp) / ptrsize) + 1
        count += 1 if print_retaddr_in_frame else 0

    # Allow invocation of "telescope a b" to dump all bytes from A to B
    if int(address) <= int(count):
        # adjust count if it is an address. use ceil division as count is number of
        # ptrsize values and we don't want to strip out a value if dest is unaligned
        count -= address
        count = max(math.ceil(count / ptrsize), 1)

    # Map of address to register string
    reg_values: DefaultDict[int, List[str]] = collections.defaultdict(list)
    for reg in pwndbg.aglib.regs.common:
        reg_values[pwndbg.aglib.regs[reg]].append(reg)

    if not inverse:
        start = address
        stop = address + (count * ptrsize)
        step = ptrsize
    else:
        start = address + ((count - 1) * ptrsize)
        stop = address - ptrsize
        step = -1 * ptrsize

    # Find all registers which show up in the trace, map address to regs
    regs: Dict[int, str] = {}
    for i in range(start, stop, step):
        values = list(reg_values[i])

        # Find all regs that point to somewhere in the current ptrsize step
        for width in range(1, pwndbg.aglib.arch.ptrsize):
            values.extend("%s-%i" % (r, width) for r in reg_values[i + width])

        regs[i] = " ".join(values)

    # Find the longest set of register information (length of string), used for padding
    if regs:
        longest_regs = max(map(len, regs.values()))
    else:
        longest_regs = 0

    # Print everything out
    result = []
    last = None
    collapse_buffer: List[str] = []
    skipped_padding = (
        2
        + len(offset_delimiter)
        + 4
        + len(offset_separator)
        + 1
        + longest_regs
        + 1
        - len(repeating_marker)
    )

    # Collapse repeating values exceeding minimum delta.
    def collapse_repeating_values() -> None:
        # The first line was already printed, hence increment by 1
        if collapse_buffer and len(collapse_buffer) + 1 >= skip_repeating_values_minimum:
            result.append(
                T.repeating_marker(
                    "%s%s%i skipped"
                    % (repeating_marker, " " * skipped_padding, len(collapse_buffer))
                )
            )
        else:
            result.extend(collapse_buffer)
        collapse_buffer.clear()

    bp = None
    if print_framepointer_offset and pwndbg.aglib.regs.frame is not None:
        # regs.frame can be None on aarch64
        bp = pwndbg.aglib.regs[pwndbg.aglib.regs.frame]

    for i, addr in enumerate(range(start, stop, step)):
        if not pwndbg.aglib.memory.peek(addr):
            collapse_repeating_values()
            result.append("<Could not read memory at %#x>" % addr)
            break
        if inverse:
            line_offset = addr - (stop + ptrsize) + (telescope.offset * ptrsize)
            idx_offset = int((start - stop - ptrsize) / ptrsize) - (i + telescope.offset)
        else:
            line_offset = addr - start + (telescope.offset * ptrsize)
            idx_offset = i + telescope.offset
        line = T.offset(
            "%02x%s%04x%s"
            % (
                idx_offset,
                delimiter,
                line_offset,
                separator,
            )
        ) + " ".join(
            (
                regs_or_frame_offset(addr, bp, regs, longest_regs),
                pwndbg.chain.format(addr),
            )
        )

        # Buffer repeating values.
        if skip_repeating_values:
            value = pwndbg.aglib.memory.pvoid(addr)
            if (
                last == value
                and addr != input_address
                and (not dont_skip_registers or not regs[addr])
            ):
                collapse_buffer.append(line)
                continue
            collapse_repeating_values()
            last = value

        result.append(line)

    collapse_repeating_values()
    telescope.offset += i
    telescope.last_address = addr

    if not to_string:
        print("\n".join(result))

    return result


def regs_or_frame_offset(addr: int, bp: int | None, regs: Dict[int, str], longest_regs: int) -> str:
    # bp only set if print_framepointer_offset=True
    if bp is None or regs[addr] or not -0xFFF <= addr - bp <= 0xFFF:
        return " " + T.register(regs[addr].ljust(longest_regs))
    else:
        # If offset to frame pointer as hex fits in hex 3 digits, print it
        return ("%+04x" % (addr - bp)).ljust(longest_regs + 1)


parser = argparse.ArgumentParser(
    description="Dereferences on stack data with specified count and offset."
)
parser.add_argument(
    "-f",
    "--frame",
    dest="frame",
    action="store_true",
    default=False,
    help="Show the stack frame, from rsp to rbp",
)

parser.add_argument(
    "-i",
    "--inverse",
    dest="inverse",
    action="store_true",
    default=False,
    help="Show reverse stack growth",
)

parser.add_argument("count", nargs="?", default=8, type=int, help="number of element to dump")
parser.add_argument(
    "offset",
    nargs="?",
    default=0,
    type=int,
    help="Element offset from $sp (support negative offset)",
)


@pwndbg.commands.Command(parser, category=CommandCategory.STACK)
@pwndbg.commands.OnlyWhenRunning
def stack(count, offset, frame, inverse) -> None:
    ptrsize = pwndbg.aglib.typeinfo.ptrsize
    telescope.repeat = stack.repeat
    telescope(
        address=pwndbg.aglib.regs.sp + offset * ptrsize, count=count, frame=frame, inverse=inverse
    )


parser = argparse.ArgumentParser(
    description="Dereferences on stack data, printing the entire stack frame with specified count and offset ."
)
parser.add_argument("count", nargs="?", default=8, type=int, help="number of element to dump")
parser.add_argument(
    "offset",
    nargs="?",
    default=0,
    type=int,
    help="Element offset from $sp (support negative offset)",
)


@pwndbg.commands.Command(parser, category=CommandCategory.STACK)
@pwndbg.commands.OnlyWhenRunning
def stackf(count, offset) -> None:
    ptrsize = pwndbg.aglib.typeinfo.ptrsize
    telescope.repeat = stack.repeat
    telescope(address=pwndbg.aglib.regs.sp + offset * ptrsize, count=count, frame=True)


telescope.last_address = 0
telescope.offset = 0
