from __future__ import annotations

import argparse

import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.lib.common import addressify_common

# Define an argument parser for the command
parser = argparse.ArgumentParser(
    prog="addressify",
    description="Converts a space-separated hex string to a little-endian address.",
)
parser.add_argument(
    "hex_string", type=str, help="Hexadecimal string to convert (e.g., '00 70 75 c1 cd ef 59 00')."
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="addressify", category=CommandCategory.MISC)
def addressify(hex_string) -> None:
    """Pwndbg command to convert hex string to little-endian address and print the result."""
    combined_args = hex_string.replace(" ", "")
    try:
        result = addressify_common(combined_args)
        print(M.success(f"{hex(result)}"))
    except Exception as e:
        print(M.error(str(e)))
