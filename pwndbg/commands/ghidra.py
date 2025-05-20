from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.ghidra
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Decompile a given function using Ghidra.")
parser.add_argument(
    "func",
    type=str,
    default=None,
    nargs="?",
    help="Function to be decompiled. Defaults to the current function.",
)


@pwndbg.commands.OnlyWithFile
@pwndbg.commands.Command(parser, category=CommandCategory.INTEGRATIONS)
def ghidra(func) -> None:
    try:
        print(pwndbg.ghidra.decompile(func))
    except Exception as e:
        print(message.error(e))
