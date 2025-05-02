from __future__ import annotations

import argparse
import string
from typing import Optional

from pwnlib.util.cyclic import cyclic
from pwnlib.util.cyclic import cyclic_find

import pwndbg.aglib.arch
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Cyclic pattern creator/finder.")

parser.add_argument(
    "-a",
    "--alphabet",
    metavar="charset",
    default=string.ascii_lowercase,
    type=str.encode,
    help="The alphabet to use in the cyclic pattern",
)

parser.add_argument(
    "-n",
    "--length",
    metavar="length",
    type=int,
    help="Size of the unique subsequences (defaults to the pointer size for the current arch)",
)


group = parser.add_mutually_exclusive_group(required=False)
group.add_argument(
    "-l",
    "-o",
    "--offset",
    "--lookup",
    dest="lookup",
    metavar="lookup_value",
    type=str,
    help="Do a lookup instead of printing the sequence (accepts constant values as well as expressions)",
)

group.add_argument(
    "count",
    type=int,
    nargs="?",
    default=100,
    help="Number of characters to print from the sequence (default: print the entire sequence)",
)

parser.add_argument(
    "filename",
    type=str,
    help="Name (path) of the file to save the cyclic pattern to",
    nargs="?",
)


@pwndbg.commands.Command(parser, command_name="cyclic", category=CommandCategory.MISC)
def cyclic_cmd(alphabet, length: Optional[int], lookup, count=100, filename="") -> None:
    if length is None:
        length = pwndbg.aglib.arch.ptrsize

    if lookup:
        lookup = pwndbg.commands.fix(lookup, sloppy=True)

        if isinstance(lookup, (pwndbg.dbg_mod.Value, int)):
            lookup = int(lookup).to_bytes(length, pwndbg.aglib.arch.endian)
        elif isinstance(lookup, str):
            lookup = bytes(lookup, "utf-8")

        if len(lookup) != length:
            print(
                message.error(
                    f"Lookup pattern must be {length} bytes (use `-n <length>` to lookup pattern of different length)"
                )
            )
            return

        hexstr = "0x" + lookup.hex()
        print(
            message.notice(
                f"Finding cyclic pattern of {length} bytes: {str(lookup)} (hex: {hexstr})"
            )
        )

        if any(c not in alphabet for c in lookup):
            print(message.error("Pattern contains characters not present in the alphabet"))
            return

        offset = cyclic_find(lookup, alphabet, length)

        if offset == -1:
            print(message.error("Given lookup pattern does not exist in the sequence"))
        else:
            print(message.success(f"Found at offset {offset}"))
    else:
        count = int(count)
        sequence = cyclic(count, alphabet, length)

        if not filename:
            print(sequence.decode())
        else:
            with open(filename, "wb") as f:
                f.write(sequence)
                print(f"Written a cyclic sequence of length {count} to file {filename}")
