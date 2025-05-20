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


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
def hex2ptr(hex_string) -> None:
    hex_string = hex_string.replace(" ", "")
    try:
        pointer = hex2ptr_common(hex_string)
        print(M.success(f"{hex(pointer)}"))
    except Exception as e:
        print(M.error(str(e)))
