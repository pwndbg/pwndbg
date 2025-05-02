from __future__ import annotations

import argparse

import pwnlib
import pwnlib.context

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Assemble shellcode into bytes")

parser.add_argument(
    "-f", "--format", default="hex", choices=["hex", "string"], type=str, help="Output format"
)

parser.add_argument(
    "--arch",
    choices=pwnlib.context.context.architectures.keys(),
    type=str,
    help="Target architecture",
)

parser.add_argument(
    "-v",
    "--avoid",
    action="append",
    help="Encode the shellcode to avoid the listed bytes (provided as hex)",
)

parser.add_argument(
    "-n",
    "--newline",
    dest="avoid",
    action="append_const",
    const="0a",
    help="Encode the shellcode to avoid newlines",
)

parser.add_argument(
    "-z",
    "--zero",
    dest="avoid",
    action="append_const",
    const="00",
    help="Encode the shellcode to avoid NULL bytes",
)

input_group = parser.add_mutually_exclusive_group(required=True)

input_group.add_argument(
    "shellcode", default=[], nargs="*", type=str, help="Assembler code to assemble"
)

input_group.add_argument("-i", "--infile", default=None, type=str, help="Specify input file")


@pwndbg.commands.Command(parser, command_name="asm", category=CommandCategory.MISC)
def asm(shellcode, format, arch, avoid, infile) -> None:
    if infile:
        print(message.warn("Going to read from file: " + infile))
        with open(infile) as file:
            shellcode = [file.read()]

    if not arch:
        arch = pwnlib.context.context.arch

    bits_for_arch = pwnlib.context.context.architectures.get(arch, {}).get("bits")
    assembly = pwnlib.asm.asm(" ".join(shellcode), arch=arch, bits=bits_for_arch)

    if avoid:
        avoid = (str(byte) for byte in avoid)
        avoid = pwnlib.unhex("".join(avoid))
        print(message.warn("Going to avoid these bytes in hex: " + avoid.hex(" ")))
        assembly = pwnlib.encode(assembly, avoid)

    if format == "hex":
        assembly = assembly.hex()

    print(assembly)
