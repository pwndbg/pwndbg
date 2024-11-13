from __future__ import annotations

import argparse

import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.lib.common import hex2ptr_common

# Define an argument parser for the command
parser = argparse.ArgumentParser(
    description="Converts a space-separated hex string to a little-endian address.",
)
parser.add_argument(
    "hex_string", type=str, help="Hexadecimal string to convert (e.g., '00 70 75 c1 cd ef 59 00')."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MISC)
def hex2ptr(hex_string) -> None:
    combined_args = hex_string.replace(" ", "")
    try:
        result = hex2ptr_common(combined_args)
        print(M.success(f"{hex(result)}"))
    except Exception as e:
        print(M.error(str(e)))
