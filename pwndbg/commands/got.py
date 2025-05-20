from __future__ import annotations

import argparse
from typing import Dict
from typing import List
from typing import Union

from elftools.elf.elffile import ELFFile

import pwndbg.aglib.arch
import pwndbg.aglib.file
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.enhance
import pwndbg.gdblib.info
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.wrappers.readelf import RelocationType

parser = argparse.ArgumentParser(
    description="""Show the state of the Global Offset Table.

Examples:
    got
    got puts
    got -p libc
    got -a
""",
)
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "-p",
    "--path",
    help="Filter results by library/objfile path.",
    type=str,
    default="",
    dest="path_filter",
)
group.add_argument(
    "-a",
    "--all",
    help="Process all libs/obfjiles including the target executable.",
    action="store_true",
    default=False,
    dest="all_",
)
parser.add_argument(
    "-r",
    "--show-readonly",
    help="Also display read-only entries (which are filtered out by default).",
    action="store_true",
    default=False,
    dest="accept_readonly",
)
parser.add_argument(
    "symbol_filter", help="Filter results by symbol name.", type=str, nargs="?", default=""
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def got(path_filter: str, all_: bool, accept_readonly: bool, symbol_filter: str) -> None:
    if pwndbg.aglib.qemu.is_qemu_usermode():
        print(
            "QEMU target detected - the result might not be accurate when checking if the entry is writable and getting the information for libraries/objfiles"
        )
        print()
    # Show the filters we are using
    if path_filter:
        print("Filtering by lib/objfile path: " + message.hint(path_filter))
    if symbol_filter:
        print("Filtering by symbol name: " + message.hint(symbol_filter))
    if not accept_readonly:
        print("Filtering out read-only entries (display them with -r or --show-readonly)")

    if path_filter or not accept_readonly or symbol_filter:
        print()

    # Calculate the base address
    if not path_filter:
        first_print = False
        _got(pwndbg.aglib.proc.exe, accept_readonly, symbol_filter)
    else:
        first_print = True

    if not all_ and not path_filter:
        return
    # TODO: We might fail to find shared libraries if GDB can't find them (can't show them in `info sharedlibrary`)
    paths = pwndbg.gdblib.info.sharedlibrary_paths()
    for path in paths:
        if path_filter not in path:
            continue
        if not first_print:
            print()
        first_print = False
        _got(path, accept_readonly, symbol_filter)

    # Maybe user have a typo or something in the path filter, show the available shared libraries
    if first_print and path_filter:
        print(message.error("No shared library matching the path filter found."))
        if paths:
            print(message.notice("Available shared libraries:"))
            for path in paths:
                print("    " + path)


def _got(path: str, accept_readonly: bool, symbol_filter: str) -> None:
    # Maybe download the file from remote
    local_path = pwndbg.aglib.file.get_file(path, try_local_path=True)

    relro_status = pwndbg.wrappers.checksec.relro_status(local_path)
    pie_status = pwndbg.wrappers.checksec.pie_status(local_path)
    got_entry = pwndbg.wrappers.readelf.get_got_entry(local_path)

    # The following code is inspired by the "got" command of https://github.com/bata24/gef/blob/dev/gef.py by @bata24, thank you!
    # TODO/FIXME: Maybe a -v option to show more information will be better
    outputs: List[Dict[str, Union[str, int]]] = []
    if path == pwndbg.aglib.proc.exe:
        bin_base_offset = pwndbg.aglib.proc.binary_base_addr if "PIE enabled" in pie_status else 0
    else:
        # TODO/FIXME: Is there a better way to get the base address of the loaded shared library?
        # I guess parsing the vmmap result might also work, but what if it's not reliable or not available? (e.g. debugging with qemu-user)
        text_section_addr = pwndbg.gdblib.info.parsed_sharedlibrary()[path][0]
        with open(local_path, "rb") as f:
            bin_base_offset = (
                text_section_addr - ELFFile(f).get_section_by_name(".text").header["sh_addr"]
            )

    # Parse the output of readelf line by line
    for category, lines in got_entry.items():
        for line in lines:
            # There are 5 fields in the output of readelf:
            # "Offset", "Info", "Type", "Sym. Value", and "Symbol's Name"
            # We only care about "Offset", "Sym. Value" and "Symbol's Name" here
            offset, _, _, *rest = line.split()[:5]
            if len(rest) < 2:
                # "Sym. Value" or "Symbol's Name" are not present in this case
                # The output of readelf might look like this (missing both value and name):
                # 00004e88  00000008 R_386_RELATIVE
                # or something like this (only missing name):
                # 00000000001ec018  0000000000000025 R_X86_64_IRELATIVE                        a0480
                # TODO: Is it possible that we are missing the value but not the name?
                value = rest[0] if rest else ""
                name = ""
            else:
                # Every fields are present in this case
                # The output of readelf might look like this:
                # 00000000001ec030  0000020a00000007 R_X86_64_JUMP_SLOT     000000000009ae80 realloc@@GLIBC_2.2.5 + 0
                value, name = rest
            address = int(offset, 16) + bin_base_offset
            # TODO/FIXME: This check might not work correctly if we failed to get the correct vmmap result
            if not accept_readonly and not pwndbg.aglib.vmmap.find(address).write:
                continue
            if not name and category == RelocationType.IRELATIVE:
                # TODO/FIXME: I don't know the naming logic behind this yet, I'm just modifying @bata24's code here :p
                # We might need to add some comments here to explain the logic in the future, and also fix it if something wrong
                if pwndbg.aglib.arch.name == "i386":
                    name = "*ABS*"
                else:
                    name = f"*ABS*+0x{int(value, 16):x}"
            if symbol_filter not in name:
                continue
            outputs.append(
                {
                    "name": name or "????",
                    "address": address,
                }
            )
    # By sorting the outputs by address, we can get a more intuitive output
    outputs.sort(key=lambda x: x["address"])
    relro_color = message.off
    if "Partial" in relro_status:
        relro_color = message.warn
    elif "Full" in relro_status:
        relro_color = message.on
    print(f"State of the GOT of {message.notice(path)}:")
    print(
        f"GOT protection: {relro_color(relro_status)} | Found {message.hint(len(outputs))} GOT entries passing the filter"
    )
    for output in outputs:
        print(
            f"[{M.get(output['address'])}] {message.hint(output['name'])} -> {pwndbg.chain.format(pwndbg.aglib.memory.pvoid(output['address']))}"  # type: ignore[arg-type]
        )
