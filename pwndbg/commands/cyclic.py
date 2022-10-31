import argparse
import string

import gdb
from pwnlib.util.cyclic import cyclic
from pwnlib.util.cyclic import cyclic_find

import pwndbg.commands
import pwndbg.gdblib.arch
from pwndbg.color import message

parser = argparse.ArgumentParser(description="Cyclic pattern creator/finder")

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


@pwndbg.commands.ArgparsedCommand(parser, command_name="cyclic")
def cyclic_cmd(alphabet, length, lookup, count=100):
    if length:
        # Convert from gdb.Value
        length = int(length)
    else:
        length = pwndbg.gdblib.arch.ptrsize

    if lookup:
        lookup = pwndbg.commands.fix(lookup, sloppy=True)

        if type(lookup) in [gdb.Value, int]:
            lookup = int(lookup).to_bytes(length, pwndbg.gdblib.arch.endian)
        elif type(lookup) is str:
            lookup = bytes(lookup, "utf-8")

        if len(lookup) != length:
            print(message.error(f"Lookup pattern must be {length} bytes"))
            return

        print(message.notice(f"Lookup value: {str(lookup)}"))

        if any(c not in alphabet for c in lookup):
            print(message.error("Pattern contains characters not present in the alphabet"))
            return

        offset = cyclic_find(lookup, alphabet, length)

        if offset == -1:
            print(message.error("Given lookup pattern does not exist in the sequence"))
        else:
            print(message.success(offset))
    else:
        sequence = cyclic(count, alphabet, length)
        print(sequence.decode())
