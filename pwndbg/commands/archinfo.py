from __future__ import annotations

import argparse

import pwndbg.aglib
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Display information about the running architecture.",
)


parser.add_argument(
    "--debug", "-d", dest="debug", action="store_true", help="print extra debugging information"
)


@pwndbg.commands.Command(parser, category=CommandCategory.PROCESS)
@pwndbg.commands.OnlyWhenRunning
def archinfo(debug: bool) -> None:

    arch_name = pwndbg.aglib.arch.name
    ptr_size = pwndbg.aglib.arch.ptrsize
    detected_platform = pwndbg.aglib.arch.platform

    additional_info = pwndbg.aglib.arch.get_additional_arch_info()

    capstone_constants = pwndbg.aglib.arch.get_capstone_constants(pwndbg.aglib.regs.pc)
    unicorn_constants = pwndbg.aglib.arch.get_unicorn_constants()

    attributes = pwndbg.aglib.arch.attributes
    attribute_names = [attribute.name for attribute in attributes]
    attribute_names_str = " ".join(attribute_names)

    print(f"Name: {arch_name} (ptrsize={ptr_size})")
    print(f"Process platform: {detected_platform.name}")

    if attribute_names_str:
        print(f"Attributes: {attribute_names_str}")

    if additional_info:
        print(additional_info)

    if debug:
        if capstone_constants is not None:
            print(
                f"Capstone constants: arch={hex(capstone_constants[0])} mode={hex(capstone_constants[1])}"
            )
        else:
            print("Capstone disassembly not supported")

        if unicorn_constants is not None:
            print(
                f"Unicorn constants: arch={hex(unicorn_constants[0])} mode={hex(unicorn_constants[1])}"
            )
        else:
            print("Unicorn emulation not supported")
