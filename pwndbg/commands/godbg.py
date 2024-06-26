from __future__ import annotations

import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.config
import pwndbg.gdblib.godbg
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Dumps a Go type at a specified address.")
parser.add_argument(
    "ty",
    type=str,
    help="Go type of value to dump, e.g. map[int]string",
)
parser.add_argument(
    "address",
    type=int,
    help="Address to dump",
)
parser.add_argument(
    "fmt", type=str, nargs="?", default="", help="Python format to format values with, e.g. <04x"
)


@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.MEMORY, command_name="go-dump", aliases=["god"]
)
@pwndbg.commands.OnlyWhenRunning
def godump(ty: str, address: int, fmt: str = "") -> None:
    parsed_ty = pwndbg.gdblib.godbg.parse_type(ty)
    print(parsed_ty.dump(address, fmt))
