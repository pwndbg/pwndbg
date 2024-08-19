"""
Hexdump implementation, ~= stolen from pwntools.
"""

from __future__ import annotations

import math
import string

import pwnlib.util.lists

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.color.hexdump as H
from pwndbg.color import theme
from pwndbg.commands.windbg import enhex

color_scheme = None
printable = None


def groupby(width: int, array, fill=None):
    return pwnlib.util.lists.group(width, array, underfull_action="fill", fill_value=fill)


config_colorize_ascii = theme.add_param(
    "hexdump-colorize-ascii", True, "whether to colorize the hexdump command ascii section"
)
config_separator = theme.add_param(
    "hexdump-ascii-block-separator", "│", "block separator char of the hexdump command"
)
config_byte_separator = theme.add_param(
    "hexdump-byte-separator",
    " ",
    "separator of single bytes in hexdump (does NOT affect group separator)",
)


@pwndbg.config.trigger(
    H.config_normal, H.config_zero, H.config_special, H.config_printable, config_colorize_ascii
)
def load_color_scheme() -> None:
    global color_scheme, printable
    #
    # We want to colorize the hex characters and only print out
    # printable values on the right hand side.
    #
    color_scheme = {i: H.normal("%02x" % i) for i in range(256)}
    printable = {i: H.normal(".") for i in range(256)}

    for c in bytearray(
        (string.ascii_letters + string.digits + string.punctuation).encode("utf-8", "ignore")
    ):
        color_scheme[c] = H.printable("%02x" % c)
        printable[c] = (
            H.printable(f"{chr(c)}") if pwndbg.config.hexdump_colorize_ascii else f"{chr(c)}"
        )

    for c in bytearray(b"\x00"):
        color_scheme[c] = H.zero("%02x" % c)
        printable[c] = H.zero(".") if pwndbg.config.hexdump_colorize_ascii else "."

    for c in bytearray(b"\xff\x7f\x80"):
        color_scheme[c] = H.special("%02x" % c)
        printable[c] = H.special(".") if pwndbg.config.hexdump_colorize_ascii else "."

    color_scheme[-1] = "  "
    printable[-1] = " "


def hexdump(
    data: bytes,
    address: int = 0,
    width: int = 16,
    group_width: int = 4,
    flip_group_endianness: bool = False,
    skip: bool = True,
    offset: int = 0,
    size: int = 0,
    count: int = 0,
    repeat: bool = False,
    dX_call: bool = False,
):
    if not dX_call:
        if not color_scheme or not printable:
            load_color_scheme()

        # If there's nothing to print, just print the offset and address and return
        if not data:
            yield H.offset(f"+{offset:04x} ") + H.address(f"{address:#08x}  ")

            # Don't allow iterating over this generator again
            return

        data = list(bytearray(data))

        # Hexdump lines to skip_lines values and yields:
        #
        # <init: skip_lines = -1>
        # line AAAA     => skip_lines =  0   => yield "AAAA"
        # line AAAA     => skip_lines =  1   => <continue>
        # line AAAA     => skip_lines = -1   => yield "skipped ..." + "AAAA"
        # line BBBB     => skip_lines = -1   => yield "BBBB"
        skip_lines = -1

        config_separator_str = H.separator(str(config_separator))
        config_byte_separator_str = str(config_byte_separator)

        groupped = groupby(width, data, fill=-1)
        before_last_idx = len(groupped) - 2

        for i, line in enumerate(groupped):
            # Handle skipping of identical lines (see skip_lines comment above)
            if skip:
                # Count lines to be skipped by checking next/future line
                if i <= before_last_idx and line == groupped[i + 1]:
                    skip_lines += 1

                    # Since we count from -1 then 0 means we are on first line
                    # We want to yield that line, so we do not continue on that counter
                    if skip_lines != 0:
                        continue

                elif skip_lines > 0:
                    out = f"... ↓            skipped {skip_lines} identical lines ({skip_lines * width} bytes)"
                    skip_lines = -1
                    yield out
                    # Fallthrough (do not continue) so we yield the current line too

            increment = i * width
            hexline = [
                H.offset(f"+{offset + increment:04x} "),
                H.address(f"{address + increment:#08x}  "),
            ]

            for group in groupby(group_width, line):
                group = reversed(group) if flip_group_endianness else group
                for idx, char in enumerate(group):
                    if flip_group_endianness and idx == group_width - 1:
                        hexline.append(H.highlight_group_lsb(color_scheme[char]))
                    else:
                        hexline.append(color_scheme[char])
                    hexline.append(config_byte_separator_str)
                hexline.append(" ")

            hexline.append(config_separator_str)
            for group in groupby(group_width, line):
                for char in group:
                    hexline.append(printable[char])
                hexline.append(config_separator_str)

            yield "".join(hexline)

    else:
        # Traditionally, windbg will display 16 bytes of data per line.
        values = []

        if repeat:
            count = hexdump.last_count
            address = hexdump.last_address
        else:
            address = int(address) & pwndbg.aglib.arch.ptrmask
            count = int(count)

        size_type = pwndbg.aglib.typeinfo.get_type(size)

        for i in range(count):
            try:
                gval = pwndbg.aglib.memory.get_typed_pointer_value(size_type, address + i * size)
                values.append(int(gval))
            except pwndbg.dbg_mod.Error:
                break

        if not values:
            print("Could not access the provided address")
            return

        n_rows = int(math.ceil(count * size / 16.0))
        row_sz = 16 // size
        rows = [values[i * row_sz : (i + 1) * row_sz] for i in range(n_rows)]
        lines = []

        for i, row in enumerate(rows):
            if not row:
                continue
            line = [enhex(pwndbg.aglib.arch.ptrsize, address + (i * 16)), "   "]
            for value in row:
                line.append(enhex(size, value))
            lines.append(" ".join(line))

        hexdump.last_count = count
        hexdump.last_address = address + len(rows) * 16

        yield lines
