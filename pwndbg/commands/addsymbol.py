from __future__ import annotations

import argparse
import hashlib
import os

import gdb

import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.symbol import create_symboled_elf

parser = argparse.ArgumentParser(description="add custom symbols")
parser.add_argument("name", type=str, help="name of the symbol")
parser.add_argument("addr", type=int, help="addr of the symbol")

SYMBOLS_CACHEDIR = pwndbg.lib.tempfile.cachedir("symbols")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def addsymbol(name, addr) -> None:
    module = pwndbg.gdblib.proc.exe
    vaddr = 0x0

    for p in pwndbg.gdblib.vmmap.get():
        if module in p.objfile:
            vaddr = p.vaddr

    path = create_symboled_elf(
        {name: addr},
        base_addr=vaddr,
        filename=os.path.join(SYMBOLS_CACHEDIR, compute_file_hash(module)),
    )

    gdb.execute(f"add-symbol-file {path} {vaddr}")


def compute_file_hash(filename: str) -> str:
    """
    Compute the MD5 hash of the file, return the hash
    """
    h = hashlib.md5()
    with open(filename, "rb") as f:
        h.update(f.read())
    return h.hexdigest()
