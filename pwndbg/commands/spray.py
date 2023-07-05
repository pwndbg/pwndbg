import argparse

import gdb
from pwnlib.util.cyclic import cyclic_gen

import pwndbg.commands

parser = argparse.ArgumentParser(description="Spray memory with a cyclic_gen() generated values")
parser.add_argument("addr", help="Address to spray")
parser.add_argument("length", nargs="?", help="Length of byte sequence", type=int, default=0)


@pwndbg.commands.ArgparsedCommand(parser)
def spray(addr, length) -> None:
    if length == 0:
        try:
            last_addr = next(p for p in pwndbg.gdblib.vmmap.get() if addr in p).end
        except StopIteration:
            last_addr = addr + 1  # Throw exception later when trying to write
        length = last_addr - int(addr)

    valueBytes = cyclic_gen().get(length)
    try:
        pwndbg.gdblib.memory.write(addr, valueBytes)
    except gdb.MemoryError as e:
        print(e)
