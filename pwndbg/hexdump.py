"""
Hexdump implementation, ~= stolen from pwntools.
"""

import math
import string

import gdb
import pwnlib.util.lists

import pwndbg.color.hexdump as H
import pwndbg.color.theme as theme
import pwndbg.gdblib.config
import pwndbg.gdblib.typeinfo
from pwndbg.commands.windbg import enhex

color_scheme = None
printable = None


def groupby(width, array, fill=None):
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


@pwndbg.gdblib.config.trigger(
    H.config_normal, H.config_zero, H.config_special, H.config_printable, config_colorize_ascii
)
def load_color_scheme():
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
            H.printable("%s" % chr(c))
            if pwndbg.gdblib.config.hexdump_colorize_ascii
            else "%s" % chr(c)
        )

    for c in bytearray(b"\x00"):
        color_scheme[c] = H.zero("%02x" % c)
        printable[c] = H.zero(".") if pwndbg.gdblib.config.hexdump_colorize_ascii else "."

    for c in bytearray(b"\xff\x7f\x80"):
        color_scheme[c] = H.special("%02x" % c)
        printable[c] = H.special(".") if pwndbg.gdblib.config.hexdump_colorize_ascii else "."

    color_scheme[-1] = "  "
    printable[-1] = " "


def hexdump(
    data,
    address=0,
    width=16,
    group_width=4,
    flip_group_endianess=False,
    skip=True,
    offset=0,
    size=0,
    count=0,
    repeat=False,
    dX_call=False,
):
    if not dX_call:
        if not color_scheme or not printable:
            load_color_scheme()

        # If there's nothing to print, just print the offset and address and return
        if len(data) == 0:
            yield H.offset("+%04x " % len(data)) + H.address("%#08x  " % (address + len(data)))

            # Don't allow iterating over this generator again
            return

        data = list(bytearray(data))
        last_line = None
        skipping = False
        for i, line in enumerate(groupby(width, data, fill=-1)):
            if skip and line == last_line:
                if skipping:
                    continue

                skipping = True
                yield "..."
            else:
                skipping = False
                last_line = line

            hexline = []

            hexline.append(H.offset("+%04x " % ((i + offset) * width)))
            hexline.append(H.address("%#08x  " % (address + (i * width))))

            for group in groupby(group_width, line):
                group = reversed(group) if flip_group_endianess else group
                for idx, char in enumerate(group):
                    if flip_group_endianess and idx == group_width - 1:
                        hexline.append(H.highlight_group_lsb(color_scheme[char]))
                    else:
                        hexline.append(color_scheme[char])
                    hexline.append(str(config_byte_separator))
                hexline.append(" ")

            hexline.append(H.separator("%s" % config_separator))
            for group in groupby(group_width, line):
                for char in group:
                    hexline.append(printable[char])
                hexline.append(H.separator("%s" % config_separator))

            yield "".join(hexline)

    else:

        # Traditionally, windbg will display 16 bytes of data per line.
        values = []

        if repeat:
            count = hexdump.last_count
            address = hexdump.last_address
        else:
            address = int(address) & pwndbg.gdblib.arch.ptrmask
            count = int(count)

        size_type = pwndbg.gdblib.typeinfo.get_type(size)

        for i in range(count):
            try:
                gval = pwndbg.gdblib.memory.poi(size_type, address + i * size)
                values.append(int(gval))
            except gdb.MemoryError:
                break

        if not values:
            print("Could not access the provided address")
            return

        n_rows = int(math.ceil(count * size / float(16)))
        row_sz = int(16 / size)
        rows = [values[i * row_sz : (i + 1) * row_sz] for i in range(n_rows)]
        lines = []

        for i, row in enumerate(rows):
            if not row:
                continue
            line = [enhex(pwndbg.gdblib.arch.ptrsize, address + (i * 16)), "   "]
            for value in row:
                line.append(enhex(size, value))
            lines.append(" ".join(line))

        hexdump.last_count = count
        hexdump.last_address = address + len(rows) * 16

        yield lines
