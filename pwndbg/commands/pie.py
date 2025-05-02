from __future__ import annotations

import argparse

import pwndbg.aglib.vmmap
import pwndbg.auxv
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
            "for specified address=0x%x and module=%s" % (offset, module)
        )
        return

    first_page = min(pages, key=lambda page: page.vaddr)

    addr = first_page.vaddr + offset

    if not any(addr in p for p in pages):
        print(
            "Offset 0x%x rebased to module %s as 0x%x is beyond module's "
            "memory pages:" % (offset, module, addr)
        )
        for p in pages:
            print(p)
        return

    return addr


parser = argparse.ArgumentParser(description="Calculate VA of RVA from PIE base.")
parser.add_argument("offset", nargs="?", default=0, help="Offset from PIE base.")
parser.add_argument(
    "module",
    type=str,
    nargs="?",
    default="",
    help="Module to choose as base. Defaults to the target executable.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def piebase(offset=None, module=None) -> None:
    offset = int(offset)
    if not module:
        module = pwndbg.aglib.proc.exe

    addr = translate_addr(offset, module)

    if addr is not None:
        print(f"Calculated VA from {module} = 0x{addr:x}")
    else:
        print(message.error("Could not calculate VA on current target."))


if pwndbg.dbg.is_gdblib_available():
    parser = argparse.ArgumentParser()
    parser.description = "Break at RVA from PIE base."
    parser.add_argument("offset", nargs="?", default=0, help="Offset to add.")
    parser.add_argument(
        "module",
        type=str,
        nargs="?",
        default="",
        help="Module to choose as base. Defaults to the target executable.",
    )

    @pwndbg.commands.Command(parser, aliases=["brva"], category=CommandCategory.BREAKPOINT)
    @pwndbg.commands.OnlyWhenRunning
    def breakrva(offset=0, module=None) -> None:
        offset = int(offset)
        if not module:
            module = pwndbg.aglib.proc.exe

        addr = translate_addr(offset, module)

        if addr is not None:
            spec = "*%#x" % (addr)
            gdb.Breakpoint(spec)
        else:
            print(message.error("Could not determine rebased breakpoint address on current target"))
