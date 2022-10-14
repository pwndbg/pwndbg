import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.config
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.hexdump

pwndbg.gdblib.config.add_param("hexdump-width", 16, "line width of hexdump command")
pwndbg.gdblib.config.add_param("hexdump-bytes", 64, "number of bytes printed by hexdump command")
pwndbg.gdblib.config.add_param(
    "hexdump-group-width",
    -1,
    "number of bytes grouped in hexdump command (If -1, the architecture's pointer size is used)",
)
pwndbg.gdblib.config.add_param(
    "hexdump-group-use-big-endian",
    False,
    "Use big-endian within each group of bytes. Only applies to raw bytes, not the ASCII part. "
    "See also hexdump-highlight-group-lsb.",
)


def address_or_module_name(s):
    gdbval_or_str = pwndbg.commands.sloppy_gdb_parse(s)
    if isinstance(gdbval_or_str, str):
        module_name = gdbval_or_str
        pages = list(filter(lambda page: module_name in page.objfile, pwndbg.gdblib.vmmap.get()))
        if pages:
            return pages[0].vaddr
        else:
            raise argparse.ArgumentError("Could not find pages for module %s" % module_name)
    elif isinstance(gdbval_or_str, (int, gdb.Value)):
        addr = gdbval_or_str
        return addr
    else:
        raise argparse.ArgumentTypeError("Unknown hexdump argument type.")


parser = argparse.ArgumentParser(
    description="Hexdumps data at the specified address or module name (or at $sp)"
)
parser.add_argument(
    "address",
    type=address_or_module_name,
    nargs="?",
    default="$sp",
    help="Address or module name to dump",
)
parser.add_argument(
    "count", nargs="?", default=pwndbg.gdblib.config.hexdump_bytes, help="Number of bytes to dump"
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def hexdump(address, count=pwndbg.gdblib.config.hexdump_bytes):
    if hexdump.repeat:
        address = hexdump.last_address
        hexdump.offset += 1
    else:
        hexdump.offset = 0

    address = int(address)
    if address > pwndbg.gdblib.arch.ptrmask:
        new_address = address & pwndbg.gdblib.arch.ptrmask
        print(
            message.warn("0x%x is larger than the maximum address, truncating to 0x%x instead"),
            address,
            new_address,
        )
        address = new_address

    count = max(int(count), 0)
    width = int(pwndbg.gdblib.config.hexdump_width)

    group_width = int(pwndbg.gdblib.config.hexdump_group_width)
    group_width = pwndbg.gdblib.typeinfo.ptrsize if group_width == -1 else group_width

    # TODO: What if arch endian is big, and use_big_endian is false?
    flip_group_endianess = (
        pwndbg.gdblib.config.hexdump_group_use_big_endian and pwndbg.gdblib.arch.endian == "little"
    )

    # The user may have input the start and end range to dump instead of the
    # starting address and the number of bytes to dump. If the address is above
    # some minimum address, and the count is larger than that address, we assume
    # this is the case and correct it
    if address > 0x10000 and count > address:
        count -= address

    try:
        data = pwndbg.gdblib.memory.read(address, count, partial=True)
        hexdump.last_address = address + count
    except gdb.error as e:
        print(e)
        return

    result = pwndbg.hexdump.hexdump(
        data,
        address=address,
        width=width,
        group_width=group_width,
        flip_group_endianess=flip_group_endianess,
        offset=hexdump.offset,
    )
    for i, line in enumerate(result):
        print(line)

    # If this command is entered again with no arguments, remember where we left off printing
    # TODO: This is broken if the user inputs a count less than the width
    hexdump.offset += i


hexdump.last_address = 0
hexdump.offset = 0
