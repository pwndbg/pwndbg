from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.hexdump
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib.config import PARAM_ZUINTEGER

pwndbg.config.add_param("hexdump-width", 16, "line width of hexdump command")
pwndbg.config.add_param("hexdump-bytes", 64, "number of bytes printed by hexdump command")
pwndbg.config.add_param(
    "hexdump-group-width",
    -1,
    "number of bytes grouped in hexdump command",
    help_docstring="If -1, the architecture's pointer size is used.",
)
pwndbg.config.add_param(
    "hexdump-group-use-big-endian",
    False,
    "use big-endian within each group of bytes in hexdump command",
    help_docstring="When `on`, use big-endian within each group of bytes. Only applies to raw bytes, not the ASCII part. "
    "See also hexdump-highlight-group-lsb.",
)
pwndbg.config.add_param(
    "hexdump-limit-mb",
    10,
    "the maximum size in megabytes (MB) `hexdump` will read",
    help_docstring="""Set the maximum size in megabytes (MB) that the `hexdump` command will attempt to read at once.
    Prevents GDB crashes due to excessive memory allocation requests.
    Set to 0 for unlimited (use with caution).""",
    param_class=PARAM_ZUINTEGER,
)


def address_or_module_name(s) -> int:
    addr_or_str: int | str = pwndbg.commands.sloppy_gdb_parse(s)
    if isinstance(addr_or_str, str):
        module_name = addr_or_str
        pages = list(filter(lambda page: module_name in page.objfile, pwndbg.aglib.vmmap.get()))
        if pages:
            return pages[0].vaddr
        else:
            raise argparse.ArgumentTypeError(f"Could not find pages for module {module_name}")
    elif isinstance(addr_or_str, int):
        return addr_or_str
    else:
        raise argparse.ArgumentTypeError("Unknown hexdump argument type.")


parser = argparse.ArgumentParser(
    description="Hexdumps data at the specified address or module name."
)
parser.add_argument(
    "address",
    type=address_or_module_name,
    nargs="?",
    default="$sp",
    help="Address or module name to dump",
)
parser.add_argument(
    "count", nargs="?", default=pwndbg.config.hexdump_bytes, help="Number of bytes to dump"
)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def hexdump(address, count=pwndbg.config.hexdump_bytes) -> None:
    if hexdump.repeat:
        address = hexdump.last_address
    else:
        hexdump.offset = 0

    address = int(address)
    if address > pwndbg.aglib.arch.ptrmask:
        new_address = address & pwndbg.aglib.arch.ptrmask
        print(
            message.warn("0x%x is larger than the maximum address, truncating to 0x%x instead"),
            address,
            new_address,
        )
        address = new_address

    if not pwndbg.aglib.memory.peek(address):
        print("Could not read memory at specified address")
        return

    count = max(int(count), 0)

    # Get the configured limit in MB
    limit_mb = int(pwndbg.config.hexdump_limit_mb)

    # Check if the limit is enabled (non-zero) and if the request count exceeds it
    if limit_mb > 0:
        limit_bytes = limit_mb * 1024 * 1024
        if count > limit_bytes:
            # Raise an error with the informative message
            raise ValueError(
                f"Hexdump count ({count}) exceeds the current limit of {limit_mb} MB.\n"
                f"Use 'set hexdump-limit-mb <new_limit_in_mb>' to increase the limit (or set to 0 for unlimited)."
            )

    width = int(pwndbg.config.hexdump_width)

    group_width = int(pwndbg.config.hexdump_group_width)
    group_width = pwndbg.aglib.typeinfo.ptrsize if group_width == -1 else group_width

    # TODO: What if arch endian is big, and use_big_endian is false?
    flip_group_endianness = (
        bool(pwndbg.config.hexdump_group_use_big_endian) and pwndbg.aglib.arch.endian == "little"
    )

    # The user may have input the start and end range to dump instead of the
    # starting address and the number of bytes to dump. If the address is above
    # some minimum address, and the count is larger than that address, we assume
    # this is the case and correct it
    if 0x10000 < address < count:
        count -= address

    try:
        data = pwndbg.aglib.memory.read(address, count, partial=True)
        hexdump.last_address = address + count
    except pwndbg.dbg_mod.Error as e:
        print(e)
        return

    result = pwndbg.hexdump.hexdump(
        data,
        address=address,
        width=width,
        group_width=group_width,
        flip_group_endianness=flip_group_endianness,
        offset=hexdump.offset,
    )

    for line in result:
        print(line)

    hexdump.offset += count


hexdump.last_address = 0
hexdump.offset = 0
