from __future__ import annotations

import argparse

import gdb

import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.symbol import _create_symboled_elf

parser = argparse.ArgumentParser(description="add custom symbols")
parser.add_argument("name", type=str, help="name of the symbol")
parser.add_argument("addr", type=int, help="addr of the symbol")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def addsymbol(name, addr) -> None:
    module = pwndbg.gdblib.proc.exe
    vaddr = 0x0

    for p in pwndbg.gdblib.vmmap.get():
        if module in p.objfile:
            vaddr = p.vaddr

    path = _create_symboled_elf({name: addr}, base_addr=vaddr)

    gdb.execute(f"add-symbol-file {path} {vaddr}")
