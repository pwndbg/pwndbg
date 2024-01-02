#!/usr/bin/env python
from __future__ import annotations

import argparse
from typing import Dict
from typing import Tuple

import gdb
from pwnlib.asm import asm
from pwnlib.asm import disasm

import pwndbg.color.context
import pwndbg.color.memory
import pwndbg.color.syntax_highlight
import pwndbg.commands
import pwndbg.gdblib.memory
import pwndbg.lib.cache
from pwndbg.color import message

# Keep old patches made so we can revert them
patches: Dict[int, Tuple[bytearray, bytearray]] = {}


parser = argparse.ArgumentParser(description="Patches given instruction with given code or bytes.")
parser.add_argument("address", type=int, help="The address to patch")
parser.add_argument("ins", type=str, help="instruction[s]")
parser.add_argument("-q", "--quiet", action="store_true", help="don't print anything")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def patch(address: gdb.Value | int, ins: str, quiet: bool) -> None:
    # Make sure that any gdb.Value object is converted to int
    address = int(address)

    new_mem = asm(ins)

    old_mem = pwndbg.gdblib.memory.read(address, len(new_mem))

    patches[address] = (old_mem, new_mem)

    pwndbg.gdblib.memory.write(address, new_mem)

    pwndbg.lib.cache.clear_caches()

    if not quiet:
        colored_addr = pwndbg.color.memory.get(address)
        print(f"Patched {len(new_mem)} bytes at {colored_addr}")


parser2 = argparse.ArgumentParser(description="Revert patch at given address.")
parser2.add_argument("address", type=int, help="Address to revert patch on")


@pwndbg.commands.ArgparsedCommand(parser2)
@pwndbg.commands.OnlyWhenRunning
def patch_revert(address: gdb.Value | int) -> None:
    # Make sure that any gdb.Value object is converted to int
    address = int(address)

    if not patches:
        print(message.notice("No patches to revert"))
        return

    if address == -1:
        for addr, (old, _new) in patches.items():
            pwndbg.gdblib.memory.write(addr, old)
            print(message.notice("Reverted patch at %#x" % addr))
        patches.clear()
    elif address in patches:
        old, _new = patches.pop(address)
        pwndbg.gdblib.memory.write(address, old)
        print(message.notice("Reverted patch at %#x" % address))
    else:
        print(message.error("Address %#x not found in patch list" % address))

    pwndbg.lib.cache.clear_caches()


parser3 = argparse.ArgumentParser(description="List all patches.")


@pwndbg.commands.ArgparsedCommand(parser3)
@pwndbg.commands.OnlyWhenRunning
def patch_list() -> None:
    if not patches:
        print(message.hint("No patches to list"))
        return

    print(pwndbg.color.context.banner("Patches:"))
    for addr, (old, new) in patches.items():
        old_insns = disasm(old, byte=False, offset=False)
        new_insns = disasm(new, byte=False, offset=False)

        colored_addr = pwndbg.color.memory.get(addr)

        old_insns, new_insns = map(
            pwndbg.color.syntax_highlight.syntax_highlight, (old_insns, new_insns)
        )

        print(
            message.hint(f"{colored_addr} ({len(new)} bytes)"),
            message.hint("\n  from:"),
            message.warn(" ".join(old_insns.replace("\n", "; ").split())),
            message.hint("\n  to  :"),
            message.warn(" ".join(new_insns.replace("\n", "; ").split())),
        )
