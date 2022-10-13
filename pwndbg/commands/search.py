import argparse
import binascii
import codecs
import os
import struct
from typing import Set

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.enhance
import pwndbg.gdblib.arch
import pwndbg.gdblib.config
import pwndbg.gdblib.vmmap
import pwndbg.search
from pwndbg.color import message

saved = set()  # type:Set[int]


def print_search_hit(address):
    """Prints out a single search hit.

    Arguments:
        address(int): Address to print
    """
    if not address:
        return

    vmmap = pwndbg.gdblib.vmmap.find(address)
    if vmmap:
        region = os.path.basename(vmmap.objfile)
    else:
        region = "[mapped]"

    region = region.ljust(15)

    region = M.get(address, region)
    addr = M.get(address)
    display = pwndbg.enhance.enhance(address)
    print(region, addr, display)


auto_save = pwndbg.gdblib.config.add_param(
    "auto-save-search", False, 'automatically pass --save to "search" command'
)

parser = argparse.ArgumentParser(
    description="""
Search memory for byte sequences, strings, pointers, and integer values
"""
)
parser.add_argument(
    "-t",
    "--type",
    choices=["byte", "short", "word", "dword", "qword", "pointer", "string", "bytes"],
    help="Size of search target",
    default="bytes",
    type=str,
)
parser.add_argument(
    "-1",
    "--byte",
    dest="type",
    action="store_const",
    const="byte",
    help="Search for a 1-byte integer",
)
parser.add_argument(
    "-2",
    "--word",
    "--short",
    dest="type",
    action="store_const",
    const="word",
    help="Search for a 2-byte integer",
)
parser.add_argument(
    "-4",
    "--dword",
    dest="type",
    action="store_const",
    const="dword",
    help="Search for a 4-byte integer",
)
parser.add_argument(
    "-8",
    "--qword",
    dest="type",
    action="store_const",
    const="qword",
    help="Search for an 8-byte integer",
)
parser.add_argument(
    "-p",
    "--pointer",
    dest="type",
    action="store_const",
    const="pointer",
    help="Search for a pointer-width integer",
)
parser.add_argument(
    "-x", "--hex", action="store_true", help="Target is a hex-encoded (for bytes/strings)"
)
parser.add_argument(
    "-e", "--executable", action="store_true", help="Search executable segments only"
)
parser.add_argument("-w", "--writable", action="store_true", help="Search writable segments only")
parser.add_argument("value", type=str, help="Value to search for")
parser.add_argument(
    "mapping_name", type=str, nargs="?", default=None, help="Mapping to search [e.g. libc]"
)
parser.add_argument(
    "--save",
    action="store_true",
    default=None,
    help="Save results for further searches with --next. Default comes from config %r"
    % auto_save.name,
)
parser.add_argument(
    "--no-save", action="store_false", default=None, dest="save", help="Invert --save"
)
parser.add_argument(
    "-n",
    "--next",
    action="store_true",
    help="Search only locations returned by previous search with --save",
)
parser.add_argument(
    "--trunc-out", action="store_true", default=False, help="Truncate the output to 20 results"
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def search(type, hex, executable, writable, value, mapping_name, save, next, trunc_out):
    global saved
    if next and not saved:
        print(
            "WARNING: cannot filter previous search results as they were empty. Performing new search saving results."
        )
        next = False
        save = True

    # Adjust pointer sizes to the local architecture
    if type == "pointer":
        type = {4: "dword", 8: "qword"}[pwndbg.gdblib.arch.ptrsize]

    if save is None:
        save = bool(pwndbg.gdblib.config.auto_save_search)

    if hex:
        try:
            value = codecs.decode(value, "hex")
        except binascii.Error as e:
            print("invalid input for type hex: {}".format(e))
            return

    # Convert to an integer if needed, and pack to bytes
    if type not in ("string", "bytes"):
        value = pwndbg.commands.fix_int(value)
        value &= pwndbg.gdblib.arch.ptrmask
        fmt = {"little": "<", "big": ">"}[pwndbg.gdblib.arch.endian] + {
            "byte": "B",
            "short": "H",
            "word": "H",
            "dword": "L",
            "qword": "Q",
        }[type]

        try:
            value = struct.pack(fmt, value)
        except struct.error as e:
            print("invalid input for type {}: {}".format(type, e))
            return

    # Null-terminate strings
    elif type == "string":
        value = value.encode()
        value += b"\x00"

    # Find the mappings that we're looking for
    mappings = pwndbg.gdblib.vmmap.get()

    if mapping_name:
        mappings = [m for m in mappings if mapping_name in m.objfile]

    if not mappings:
        print(message.error("Could not find mapping %r" % mapping_name))
        return

    # If next is passed, only perform a manual search over previously saved addresses
    print("Searching for value: " + repr(value))
    if next:
        val_len = len(value)
        new_saved = set()

        i = 0
        for addr in saved:
            try:
                val = pwndbg.gdblib.memory.read(addr, val_len)
            except Exception:
                continue
            if val == value:
                new_saved.add(addr)
                if not trunc_out or i < 20:
                    print_search_hit(addr)
                i += 1

        print("Search found %d items" % i)
        saved = new_saved
        return

    # Prep the saved set if necessary
    if save:
        saved = set()

    # Perform the search
    i = 0
    for address in pwndbg.search.search(
        value, mappings=mappings, executable=executable, writable=writable
    ):

        if save:
            saved.add(address)

        if not trunc_out or i < 20:
            print_search_hit(address)
        i += 1
