import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.memory


def xor_memory(address, key, count):
    """
    Helper function for xorring memory in gdb
    """
    mem = pwndbg.gdblib.memory.read(address, count, partial=True)

    for index, byte in enumerate(mem):
        key_index = index % len(key)
        mem[index] = byte ^ ord(key[key_index])

    return mem


parser = argparse.ArgumentParser(description="XOR `count` bytes at address` with the key key`.")
parser.add_argument(
    "address", type=pwndbg.commands.sloppy_gdb_parse, help="The address to start xoring at."
)
parser.add_argument("key", type=str, help="The key to use.")
parser.add_argument("count", type=int, help="The number of bytes to xor.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def xor(address, key, count):
    try:
        xorred_memory = xor_memory(address, key, count)
        pwndbg.gdblib.memory.write(address, xorred_memory)
    except gdb.error as e:
        print(e)


parser = argparse.ArgumentParser(description="Memfrobs a region of memory (xor with '*').")
parser.add_argument("address", type=int, help="The address to start xoring at.")
parser.add_argument("count", type=int, help="The number of bytes to xor.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def memfrob(address, count):
    return xor(address, "*", count)
