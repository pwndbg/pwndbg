from __future__ import annotations

import argparse
from typing import cast

import pwndbg.aglib
import pwndbg.aglib.asm
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE

parser = argparse.ArgumentParser(description="Assemble shellcode into bytes")

parser.add_argument(
    "-f", "--format", default="hex", choices=["hex", "string"], type=str, help="Output format"
)

parser.add_argument(
    "--arch",
    choices=PWNDBG_SUPPORTED_ARCHITECTURES,
    type=str,
    help="Target architecture",
)

input_group = parser.add_mutually_exclusive_group(required=True)

input_group.add_argument(
    "shellcode", default=[], nargs="*", type=str, help="Assembler code to assemble"
)

input_group.add_argument("-i", "--infile", default=None, type=str, help="Specify input file")


@pwndbg.commands.Command(parser, command_name="asm", category=CommandCategory.MISC)
def asm(shellcode: list[str], format: str, arch: str | None, infile: str) -> None:
    if infile:
        print(message.warn("Going to read from file: " + infile))
        with open(infile) as file:
            shellcode = [file.read()]

    if arch is None:
        # We want to use the current architecture.
        # But check first that it is actually set.
        if pwndbg.aglib.arch is None:
            print(
                message.error("No architecture currently set.") + " Pass it in the --arch argument."
            )
            return
        assembly: bytes = pwndbg.aglib.asm.asm(" ".join(shellcode))
    else:
        # Is enforced by argparse.
        assert arch in PWNDBG_SUPPORTED_ARCHITECTURES
        assembly = pwndbg.aglib.asm.asm_for_arch(
            " ".join(shellcode), cast(PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, arch)
        )

    if format == "hex":
        print(assembly.hex())
    else:
        print(assembly)
