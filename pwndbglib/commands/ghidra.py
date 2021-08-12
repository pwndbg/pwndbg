import argparse

import pwndbglib.color.message as message
import pwndbglib.commands
import pwndbglib.ghidra

parser = argparse.ArgumentParser()
parser.description = """Decompile a given function using ghidra"""
parser.add_argument("func", type=str, default=None, nargs="?", help="Function to be decompiled. Defaults to the current function.")


@pwndbglib.commands.OnlyWithFile
@pwndbglib.commands.ArgparsedCommand(parser)
def ghidra(func):
    try:
        print(pwndbglib.ghidra.decompile(func))
    except Exception as e:
        print(message.error(e))
