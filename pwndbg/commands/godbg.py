from __future__ import annotations

import argparse

import pwndbg.aglib.godbg
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Dumps a Go value of a given type at a specified address."
)
parser.add_argument(
    "ty",
    type=str,
    help="Go type of value to dump, e.g. map[int]string, or the address of a type to resolve at runtime, e.g. 0x408860",
)
parser.add_argument(
    "address",
    type=pwndbg.commands.AddressExpr,
    help="Address to dump",
)
parser.add_argument("-x", "--hex", action="store_true", help="Display non-pointer integers as hex")
parser.add_argument(
    "-f",
    "--decimals",
    nargs="?",
    type=int,
    help="Configures the number of decimal places to display for floating points",
)

parser.add_argument(
    "-d",
    "--debug",
    action="store_true",
    help="Shows debug info, like addresses for slice/map elements, slice capacity, etc.",
)

parser.add_argument(
    "-p",
    "--pretty",
    action="store_true",
    help="Enables pretty printing",
)


@pwndbg.commands.Command(
    parser, category=CommandCategory.MEMORY, command_name="go-dump", aliases=["god"]
)
@pwndbg.commands.OnlyWhenRunning
def go_dump(
    ty: str, address: int, hex: bool, decimals: int | None, debug: bool, pretty: bool
) -> None:
    try:
        ty_addr = int(ty, 0)
        (_, parsed_ty) = pwndbg.aglib.godbg.decode_runtime_type(ty_addr)
        if parsed_ty is None:
            print("Failed to decode runtime type.")
            return
    except ValueError:
        parsed_ty = pwndbg.aglib.godbg.parse_type(ty)
    fmt = pwndbg.aglib.godbg.FormatOpts(
        int_hex=hex, float_decimals=decimals, debug=debug, pretty=pretty
    )
    print(parsed_ty.dump(address, fmt))


parser = argparse.ArgumentParser(
    description="Dumps a Go runtime reflection type at a specified address."
)
parser.add_argument(
    "address",
    type=pwndbg.commands.AddressExpr,
    help="Address to dump",
)


@pwndbg.commands.Command(
    parser, category=CommandCategory.MEMORY, command_name="go-type", aliases=["goty"]
)
@pwndbg.commands.OnlyWhenRunning
def go_type(address: int) -> None:
    meta, ty = pwndbg.aglib.godbg.decode_runtime_type(address, True)
    print(f" Name: {meta.name}")
    print(f" Kind: {meta.kind.name}")
    print(f" Size: {meta.size} ({meta.size:#x})")
    print(f"Align: {meta.align}")
    print(f"Parse: {ty}")
    if ty:
        data = ty.additional_metadata()
        if data:
            print("\n".join(data))
