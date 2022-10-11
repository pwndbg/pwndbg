#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse

from pwnlib.asm import asm
from pwnlib.asm import disasm

import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.gdblib.memory
import pwndbg.lib.memoize

# Keep old patches made so we can revert them
patches = {}


parser = argparse.ArgumentParser(description="Patches given instruction with given code or bytes")
parser.add_argument("address", type=int, help="The address to patch")
parser.add_argument("ins", type=str, help="instruction[s]")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def patch(address, ins):
    new_mem = asm(ins)

    old_mem = pwndbg.gdblib.memory.read(address, len(new_mem))

    patches[address] = (old_mem, new_mem)

    pwndbg.gdblib.memory.write(address, new_mem)

    pwndbg.lib.memoize.reset()


parser2 = argparse.ArgumentParser(description="Revert patch at given address")
parser2.add_argument("address", type=int, help="Address to revert patch on")


@pwndbg.commands.ArgparsedCommand(parser2)
@pwndbg.commands.OnlyWhenRunning
def patch_revert(address):
    if not patches:
        print(message.notice("No patches to revert"))
        return

    if address == -1:
        for addr, (old, _new) in patches.items():
            pwndbg.gdblib.memory.write(addr, old)
            print(message.notice("Reverted patch at %#x" % addr))
        patches.clear()
    else:
        old, _new = patches[address]
        pwndbg.gdblib.memory.write(address, old)

    pwndbg.lib.memoize.reset()


parser3 = argparse.ArgumentParser(description="List all patches")


@pwndbg.commands.ArgparsedCommand(parser3)
@pwndbg.commands.OnlyWhenRunning
def patch_list():
    if not patches:
        print(message.hint("No patches to list"))
        return

    print(message.hint("Patches:"))
    for addr, (old, new) in patches.items():
        old_insns = disasm(old)
        new_insns = disasm(new)

        print(
            message.hint("Patch at"),
            message.warning("%#x:" % addr),
            message.hint("from"),
            message.warning(old_insns.replace("\n", "; ")),
            message.hint("to"),
            message.warning(new_insns.replace("\n", "; ")),
        )
