from __future__ import annotations

import argparse
import binascii
import codecs
import os
import struct
from typing import Set

import pwnlib

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.vmmap
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.enhance
import pwndbg.search
from pwndbg.color import message
from pwndbg.commands import CommandCategory

if pwndbg.dbg.is_gdblib_available():
    import gdb

saved: Set[int] = set()


def print_search_hit(address: int) -> None:
    """Prints out a single search hit.

    Arguments:
        address: Address to print
    """
    if not address:
        return

    vmmap = pwndbg.aglib.vmmap.find(address)
    if vmmap:
        region = os.path.basename(vmmap.objfile)
    else:
        region = "[mapped]"

    region = region.ljust(15)

    region = M.get(address, region)
    addr = M.get(address)
    display = pwndbg.enhance.enhance(address)
    print(region, addr, display)


auto_save = pwndbg.config.add_param(
    "auto-save-search", False, 'automatically pass --save to "search" command'
)
parser = argparse.ArgumentParser(
    description="""Search memory for byte sequences, strings, pointers, and integer values.

By default search results are cached. If you want to cache all results, but only print a subset, use --trunc-out. If you want to cache only a subset of results, and print the results immediately, use --limit. The latter is specially useful if you're searching a huge section of memory.

""",
)
parser.add_argument(
    "-t",
    "--type",
    choices=["byte", "short", "word", "dword", "qword", "pointer", "string", "bytes", "asm"],
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
    "--asm",
    dest="type",
    action="store_const",
    const="asm",
    help="Search for an assembly instruction",
)
parser.add_argument(
    "--arch",
    choices=pwnlib.context.context.architectures.keys(),
    type=str,
    help="Target architecture",
)
parser.add_argument(
    "--asmbp", action="store_true", help="Set breakpoint for found assembly instruction"
)
parser.add_argument(
    "-x", "--hex", action="store_true", help="Target is a hex-encoded (for bytes/strings)"
)
parser.add_argument(
    "-e", "--executable", action="store_true", help="Search executable segments only"
)
parser.add_argument("-w", "--writable", action="store_true", help="Search writable segments only")
parser.add_argument(
    "-s",
    "--step",
    default=None,
    type=str,
    help="Step search address forward to next alignment after each hit (ex: 0x1000)",
)
parser.add_argument(
    "-l",
    "--limit",
    default=None,
    type=str,
    help="Max results before quitting the search. Differs from --trunc-out in that it will not save all search results before quitting",
)
parser.add_argument(
    "-a", "--aligned", default=None, type=str, help="Result must be aligned to this byte boundary"
)
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
    "--trunc-out",
    action="store_true",
    default=False,
    help="Truncate the output to 20 results. Differs from --limit in that it will first save all search results",
)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def search(
    type,
    arch,
    asmbp,
    hex,
    executable,
    writable,
    step,
    limit,
    aligned,
    value,
    mapping_name,
    save,
    next,
    trunc_out,
) -> None:
    global saved
    if next and not saved:
        print(
            "WARNING: cannot filter previous search results as they were empty. Performing new search saving results."
        )
        next = False
        save = True

    if not arch:
        arch = pwnlib.context.context.arch

    # Initialize is_pointer to track whether the search type is a pointer
    is_pointer = None
    # Adjust pointer sizes to the local architecture
    if type == "pointer":
        type = {4: "dword", 8: "qword"}[pwndbg.aglib.arch.ptrsize]
        is_pointer = True

    if save is None:
        save = bool(pwndbg.config.auto_save_search)

    if hex:
        try:
            value = codecs.decode(value, "hex")
        except binascii.Error as e:
            print(f"invalid input for type hex: {e}")
            return

    if step:
        step = pwndbg.commands.fix_int(step)

    if aligned:
        aligned = pwndbg.commands.fix_int(aligned)

    if limit:
        limit = pwndbg.commands.fix_int(limit)
    # Convert to an integer if needed, and pack to bytes
    if type not in ("string", "bytes", "asm"):
        value = pwndbg.commands.fix_int(value)
        value &= pwndbg.aglib.arch.ptrmask
        fmt = {"little": "<", "big": ">"}[pwndbg.aglib.arch.endian] + {
            "byte": "B",
            "short": "H",
            "word": "H",
            "dword": "L",
            "qword": "Q",
        }[type]

        try:
            value = struct.pack(fmt, value)
        except struct.error as e:
            print(f"invalid input for type {type}: {e}")
            return

    # Null-terminate strings
    elif type == "string":
        value = value.encode()
        value += b"\x00"

    elif type == "asm" or asmbp:
        bits_for_arch = pwnlib.context.context.architectures.get(arch, {}).get("bits")
        value = pwnlib.asm.asm(value, arch=arch, bits=bits_for_arch)

    # `pwndbg.search.search` expects a `bytes` object for its pattern. Convert the string pattern we
    # were given to a bytes object by encoding it as an UTF-8 byte sequence. This matches the behavior
    # we previously got by calling `gdb.Inferior.search_memory` with an `str`, since right about GDB
    # version 7.x or 8.x[1], as it uses a `Py_buffer` object populated with an `'s*'` pattern, which
    # has been encoding `str` object as a UTF-8 byte sequence since Python 3.1[2].
    #
    # [1]: https://sourceware.org/git/?p=binutils-gdb.git;a=blame;f=gdb/python/py-inferior.c;h=a1042ee72ac733091f7572bc04b072546d3c1519;hb=23c84db5b3cb4e8a0d555c76e1a0ab56dc8355f3
    # [2]: https://docs.python.org/3.1/c-api/arg.html#strings-and-buffers

    elif type == "bytes" and not hex:
        try:
            value = value.encode("utf-8")
        except UnicodeError as what:
            print(
                message.error(
                    f"Invalid pattern '{value}'. Patterns of type `bytes` must be encodable in UTF-8: {what}"
                )
            )
            return

    # Find the mappings that we're looking for
    mappings = pwndbg.aglib.vmmap.get()

    if mapping_name:
        mappings = [m for m in mappings if mapping_name in m.objfile]

    if not mappings:
        print(message.error("Could not find mapping %r" % mapping_name))
        return

    # Output appropriate messages based on the detected search type for better clarity
    if is_pointer:
        print("Searching for a pointer-width integer: " + repr(value))
    elif type == "word" or type == "short":
        print("Searching for a 2-byte integer: " + repr(value))
    elif type == "dword":
        print("Searching for a 4-byte integer: " + repr(value))
    elif type == "qword":
        print("Searching for an 8-byte integer: " + repr(value))
    elif type == "string":
        print("Searching for string: " + repr(value))
    # If next is passed, only perform a manual search over previously saved addresses
    elif type == "asm" or asmbp:
        print("Searching for instruction (assembled value): " + repr(value))
    else:
        print("Searching for byte: " + repr(value))

    if next:
        val_len = len(value)
        new_saved = set()

        i = 0
        for addr in saved:
            try:
                val = pwndbg.aglib.memory.read(addr, val_len)
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
        value,
        mappings=mappings,
        executable=executable,
        writable=writable,
        step=step,
        aligned=aligned,
        limit=limit,
    ):
        if save:
            saved.add(address)
        if asmbp:
            if pwndbg.dbg.is_gdblib_available():
                # set breakpoint on the instruction
                gdb.Breakpoint("*%#x" % address, temporary=False)
            else:
                print(
                    f"breakpoints are not supported outside of GDB yet, would be set at {address:#x}"
                )

        if not trunc_out or i < 20:
            print_search_hit(address)
        i += 1
