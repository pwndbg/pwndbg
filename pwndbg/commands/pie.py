from __future__ import annotations

import argparse

import pwndbg.aglib.proc
import pwndbg.aglib.vmmap
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

if pwndbg.dbg.is_gdblib_available():
    import gdb


def translate_addr(offset, module):
    mod_filter = lambda page: module in page.objfile
    pages = list(filter(mod_filter, pwndbg.aglib.vmmap.get()))

    if not pages:
        print(
            "There are no memory pages in `vmmap` "
            f"for specified address=0x{offset:x} and module={module}"
        )
        return None

    first_page = min(pages, key=lambda page: page.vaddr)

    addr = first_page.vaddr + offset

    if not any(addr in p for p in pages):
        print(
            f"Offset 0x{offset:x} rebased to module {module} as 0x{addr:x} is beyond module's "
            "memory pages:"
        )
        for p in pages:
            print(p)
        return None

    return addr


parser = argparse.ArgumentParser(description="Calculate VA of RVA from PIE base.")
parser.add_argument("offset", nargs="?", type=int, default=0, help="Offset from PIE base.")
parser.add_argument(
    "module",
    type=str,
    nargs="?",
    default="",
    help="Module to choose as base. Defaults to the target executable.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def piebase(offset: int = 0, module: str = "") -> None:
    offset = int(offset)
    if not module:
        module = pwndbg.aglib.proc.exe()

    addr = translate_addr(offset, module)

    if addr is not None:
        print(f"Calculated VA from {module} = 0x{addr:x}")
    else:
        print(message.error("Could not calculate VA on current target."))


if pwndbg.dbg.is_gdblib_available():
    parser = argparse.ArgumentParser()
    parser.description = "Break at RVA from PIE base."
    parser.add_argument("offset", nargs="?", type=int, default=0, help="Offset to add.")
    parser.add_argument(
        "module",
        type=str,
        nargs="?",
        default="",
        help="Module to choose as base. Defaults to the target executable.",
    )

    @pwndbg.commands.Command(parser, aliases=["brva"], category=CommandCategory.BREAKPOINT)
    @pwndbg.commands.OnlyWhenRunning
    def breakrva(offset: int = 0, module: str = "") -> None:
        offset = int(offset)
        if not module:
            module = pwndbg.aglib.proc.exe()

        addr = translate_addr(offset, module)

        if addr is not None:
            spec = f"*{addr:#x}"
            gdb.Breakpoint(spec)
        else:
            print(message.error("Could not determine rebased breakpoint address on current target"))
