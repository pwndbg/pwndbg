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
parser.add_argument("--value", help="Value to spray memory with", type=str, required=False)


@pwndbg.commands.ArgparsedCommand(parser)
def spray(addr, length, value) -> None:
    if length == 0:
        last_addr = addr
        for p in pwndbg.gdblib.vmmap.get():
            if addr in p:
                last_addr = p.end
                break
        length = last_addr - int(addr)

        if length == 0:
            print(M.error("Invalid address, can't find end of vmmap"))
            return

    value_bytes = b""

    if value:
        if value.startswith("0x"):
            strlen = len(value[2:])
            if strlen & 1:  # 0x1, 0x123...
                strlen += 1
            value_bytes = int(value, 16).to_bytes(int(strlen / 2), byteorder="big")
        else:
            value_bytes = bytes(value, "utf-8")

        value_length = len(value_bytes)
        value_bytes = value_bytes * int(length / value_length)

        if length % value_length != 0:
            value_bytes += value_bytes[: (length % value_length)]
    else:
        value_bytes = cyclic(length, n=pwndbg.gdblib.arch.ptrsize)

    try:
        pwndbg.gdblib.memory.write(addr, value_bytes)
    except gdb.MemoryError as e:
        print(M.error(e))
