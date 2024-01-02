from __future__ import annotations

import argparse

import gdb
from pwnlib.util.cyclic import cyclic

import pwndbg.color.message as M
import pwndbg.commands

parser = argparse.ArgumentParser(description="Spray memory with cyclic() generated values")
parser.add_argument("addr", help="Address to spray")
parser.add_argument(
    "length",
    help="Length of byte sequence, when unspecified sprays until the end of vmmap which address belongs to",
    type=int,
    nargs="?",
    default=0,
)
parser.add_argument(
    "--value",
    help="Value to spray memory with, when prefixed with '0x' treated as hex string encoded big-endian",
    type=str,
    required=False,
)
parser.add_argument(
    "-x",
    "--only-funcptrs",
    help="Spray only addresses whose values points to executable pages",
    action="store_true",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def spray(addr, length, value, only_funcptrs) -> None:
    if length == 0:
        page = pwndbg.gdblib.vmmap.find(addr)
        if page is None:
            print(
                M.error(
                    f"Invalid address {addr}: can't find vmmap containing it to determine the spray length"
                )
            )
            return
        length = page.end - int(addr)

    value_bytes = b""

    if value:
        if value.startswith("0x"):
            value_bytes = int(value, 16).to_bytes((len(value[2:]) + 1) // 2, byteorder="big")
        else:
            value_bytes = bytes(value, "utf-8")

        value_length = len(value_bytes)
        value_bytes = value_bytes * (int(length) // value_length)

        if length % value_length != 0:
            value_bytes += value_bytes[: (length % value_length)]
    else:
        value_bytes = cyclic(length, n=pwndbg.gdblib.arch.ptrsize)

    try:
        if only_funcptrs:
            mem = pwndbg.gdblib.memory.read(addr, length)

            addresses_written = 0
            ptrsize = pwndbg.gdblib.arch.ptrsize
            for i in range(0, len(mem) - (length % ptrsize), ptrsize):
                ptr_candidate = pwndbg.gdblib.arch.unpack(mem[i : i + ptrsize])
                page = pwndbg.gdblib.vmmap.find(ptr_candidate)
                if page is not None and page.execute:
                    pwndbg.gdblib.memory.write(addr + i, value_bytes[i : i + ptrsize])
                    addresses_written += 1
            print(M.notice(f"Overwritten {addresses_written} function pointers"))
        else:
            pwndbg.gdblib.memory.write(addr, value_bytes)
    except gdb.MemoryError as e:
        print(M.error(e))
