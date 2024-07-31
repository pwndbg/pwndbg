from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.config
import pwndbg.gdblib.godbg
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Dumps a Go value of a given type at a specified address."
)
parser.add_argument(
    "ty",
    type=str,
    help="Go type of value to dump, e.g. map[int]string",
)
parser.add_argument(
    "address",
    type=pwndbg.commands.AddressExpr,
    help="Address to dump",
)
parser.add_argument(
    "fmt", type=str, nargs="?", default="", help="Python format to format values with, e.g. <04x"
)


@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.MEMORY, command_name="go-dump", aliases=["god"]
)
@pwndbg.commands.OnlyWhenRunning
def go_dump(ty: str, address: int | str, fmt: str = "") -> None:
    address = int(address)
    parsed_ty = pwndbg.gdblib.godbg.parse_type(ty)
    print(parsed_ty.dump(address, fmt))


parser = argparse.ArgumentParser(
    description="Dumps a Go runtime reflection type at a specified address."
)
parser.add_argument(
    "address",
    type=pwndbg.commands.AddressExpr,
    help="Address to dump",
)


@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.MEMORY, command_name="go-type", aliases=["goty"]
)
@pwndbg.commands.OnlyWhenRunning
def go_type(address: int | str) -> None:
    address = int(address)
    meta, ty = pwndbg.gdblib.godbg.decode_runtime_type(address)
    print(f" Name: {meta.name}")
    print(f" Kind: {meta.kind.name}")
    print(f" Size: {meta.size} ({meta.size:#x})")
    print(f"Align: {meta.align}")
    print(f"Parse: {ty}")
