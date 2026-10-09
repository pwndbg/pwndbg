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

    additional_info = pwndbg.aglib.arch.get_additional_arch_info()

    capstone_constants = pwndbg.aglib.arch.get_capstone_constants(pwndbg.aglib.regs.pc)
    unicorn_constants = pwndbg.aglib.arch.get_unicorn_constants()

    print(f"Name: {arch_name}")

    if additional_info:
        print(additional_info)

    if debug:
        print(
            f"Capstone constants: arch={hex(capstone_constants[0])} mode={hex(capstone_constants[1])}"
        )
        print(
            f"Unicorn constants: arch={hex(unicorn_constants[0])} mode={hex(unicorn_constants[1])}"
        )
