"""
Prints out pointer chains starting at some address in memory.

Generally used to print out the stack or register values.
"""

import argparse
import collections
import math

import pwndbg.chain
import pwndbg.color.telescope as T
import pwndbg.color.theme as theme
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.config
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.typeinfo

telescope_lines = pwndbg.gdblib.config.add_param(
    "telescope-lines", 8, "number of lines to printed by the telescope command"
)
skip_repeating_values = pwndbg.gdblib.config.add_param(
    "telescope-skip-repeating-val",
    True,
    "whether to skip repeating values of the telescope command",
)
skip_repeating_values_minimum = pwndbg.gdblib.config.add_param(
    "telescope-skip-repeating-val-minimum",
    3,
    "minimum amount of repeated values before skipping lines",
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
    description="""
    Recursively dereferences pointers starting at the specified address
    ($sp by default)
    """
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
    "address", nargs="?", default=None, type=int, help="The address to telescope at."
)

parser.add_argument(
    "count", nargs="?", default=telescope_lines, type=int, help="The number of lines to show."
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def telescope(address=None, count=telescope_lines, to_string=False, reverse=False):
    """
    Recursively dereferences pointers starting at the specified address
    ($sp by default)
    """
    ptrsize = pwndbg.gdblib.typeinfo.ptrsize
    if telescope.repeat:
        address = telescope.last_address + ptrsize
        telescope.offset += 1
    else:
        telescope.offset = 0

    address = int(address if address else pwndbg.gdblib.regs.sp) & pwndbg.gdblib.arch.ptrmask
    count = max(int(count), 1) & pwndbg.gdblib.arch.ptrmask
    delimiter = T.delimiter(offset_delimiter)
    separator = T.separator(offset_separator)

    # Allow invocation of "telescope 20" to dump 20 bytes at the stack pointer
    if address < pwndbg.gdblib.memory.MMAP_MIN_ADDR and not pwndbg.gdblib.memory.peek(address):
        count = address
        address = pwndbg.gdblib.regs.sp

    # Allow invocation of telescope -r to dump previous addresses
    if reverse:
        address -= (count - 1) * ptrsize

    # Allow invocation of "telescope a b" to dump all bytes from A to B
    if int(address) <= int(count):
        # adjust count if it is an address. use ceil division as count is number of
        # ptrsize values and we don't want to strip out a value if dest is unaligned
        count -= address
        count = max(math.ceil(count / ptrsize), 1)

    reg_values = collections.defaultdict(lambda: [])
    for reg in pwndbg.gdblib.regs.common:
        reg_values[pwndbg.gdblib.regs[reg]].append(reg)

    start = address
    stop = address + (count * ptrsize)
    step = ptrsize

    # Find all registers which show up in the trace
    regs = {}
    for i in range(start, stop, step):
        values = list(reg_values[i])

        for width in range(1, pwndbg.gdblib.arch.ptrsize):
            values.extend("%s-%i" % (r, width) for r in reg_values[i + width])

        regs[i] = " ".join(values)

    # Find the longest set of register information
    if regs:
        longest_regs = max(map(len, regs.values()))
    else:
        longest_regs = 0

    # Print everything out
    result = []
    last = None
    collapse_buffer = []
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
    def collapse_repeating_values():
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

    for i, addr in enumerate(range(start, stop, step)):
        if not pwndbg.gdblib.memory.peek(addr):
            collapse_repeating_values()
            result.append("<Could not read memory at %#x>" % addr)
            break

        line = " ".join(
            (
                T.offset(
                    "%02x%s%04x%s"
                    % (
                        i + telescope.offset,
                        delimiter,
                        addr - start + (telescope.offset * ptrsize),
                        separator,
                    )
                ),
                T.register(regs[addr].ljust(longest_regs)),
                pwndbg.chain.format(addr),
            )
        )

        # Buffer repeating values.
        if skip_repeating_values:
            value = pwndbg.gdblib.memory.pvoid(addr)
            if last == value:
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


parser = argparse.ArgumentParser(
    description="dereferences on stack data with specified count and offset."
)
parser.add_argument("count", nargs="?", default=8, type=int, help="number of element to dump")
parser.add_argument(
    "offset",
    nargs="?",
    default=0,
    type=int,
    help="Element offset from $sp (support negative offset)",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def stack(count, offset):
    ptrsize = pwndbg.gdblib.typeinfo.ptrsize
    telescope.repeat = stack.repeat
    telescope(address=pwndbg.gdblib.regs.sp + offset * ptrsize, count=count)


telescope.last_address = 0
telescope.offset = 0
