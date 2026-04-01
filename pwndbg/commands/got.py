from __future__ import annotations

import argparse
from collections.abc import Iterator

import pwndbg.aglib
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.color.memory as mem_color
import pwndbg.commands
import pwndbg.lib.got
import pwndbg.lib.memory
import pwndbg.wrappers.checksec
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib.got import RelocationType

parser = argparse.ArgumentParser(
    description="Show the state of the Global Offset Table.",
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


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.LINUX,
    examples="""
>got
    Print all writable GOT entries in the executable.
>got -r puts
    Print all GOT entries that contain the string "puts".
>got -p libc
    Print all writable GOT entries used by libc. (And any other loaded
    object files that contain the string "libc" in their path).
>got -ra
    Print all GOT entries in the address space.
""",
)
@pwndbg.commands.OnlyWhenRunning
def got(path_filter: str, all_: bool, accept_readonly: bool, symbol_filter: str) -> None:
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
        _got(pwndbg.aglib.proc.exe(), accept_readonly, symbol_filter)
    else:
        first_print = True

    if not all_ and not path_filter:
        return

    paths = [o.objfile for o in iter_objfiles()]
    paths.sort()
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
    got_entry = pwndbg.lib.got.get_got_entry(local_path)

    # The following code is inspired by the "got" command of https://github.com/bata24/gef/blob/dev/gef.py by @bata24, thank you!
    # TODO/FIXME: Maybe a -v option to show more information will be better
    outputs: list[dict[str, str | int]] = []
    if path == pwndbg.aglib.proc.exe():
        bin_base_offset = pwndbg.aglib.proc.binary_base_addr() if "PIE enabled" in pie_status else 0
    else:
        page = next(filter(lambda o: o.objfile == path, iter_objfiles()), None)
        assert page is not None, f"unable to find vmmap entry for objfile: {path}"
        bin_base_offset = page.start

    # Process each GOT relocation entry
    for category, entries in got_entry.items():
        for entry in entries:
            offset = entry["offset"]
            value = entry["value"]
            name = entry["name"]

            # Type narrowing assertions
            assert isinstance(offset, int)
            assert isinstance(value, int)
            assert isinstance(name, str)

            address = offset + bin_base_offset
            # TODO/FIXME: This check might not work correctly if we failed to get the correct vmmap result
            if not accept_readonly and not pwndbg.aglib.vmmap.find(address).write:
                continue
            if not name and category == RelocationType.IRELATIVE:
                # I'm not entirely sure why this naming logic exists, but I'm preserving
                # the behavior from the original implementation (credit to @bata24).
                # If we figure out the "why" later, we should update this comment!
                if pwndbg.aglib.arch.name == "i386":
                    name = "*ABS*"
                else:
                    name = f"*ABS*+0x{value:x}"
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
            f"[{mem_color.get(output['address'])}] {message.hint(output['name'])} -> {pwndbg.chain.format(pwndbg.aglib.memory.read_pointer_width(output['address']))}"  # type: ignore[arg-type]
        )


def iter_objfiles() -> Iterator[pwndbg.lib.memory.Page]:
    main = pwndbg.aglib.proc.exe()
    uniq = set()

    for page in pwndbg.aglib.vmmap.get():
        if page.objfile == main:
            # Skip main elf
            continue
        if not page.is_memory_mapped_file:
            # Skip virtual objfiles eg: `[vdso]` etc..
            continue
        if page.objfile in uniq:
            continue
        uniq.add(page.objfile)
        yield page
