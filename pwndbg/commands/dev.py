from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.disasm
import pwndbg.gdblib.nearpc

parser = argparse.ArgumentParser(description="Dump internal PwndbgInstruction attributes.")

# We don't have a parser to pass in true/false in arguments, so there are two args to force the enabling/disabling of emulation
parser.add_argument(
    "-e",
    "--emulate",
    dest="force_emulate",
    action="store_true",
    default=False,
    help="Force the use of emulation when enhancing the instruction, regardless of global 'emulate' setting.",
)

parser.add_argument(
    "-n",
    "--no-emulate",
    dest="no_emulate",
    action="store_true",
    default=False,
    help="Disable the use of emulation when enhancing the instruction, regardless of global 'emulate' setting.",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dev_dump_instruction(force_emulate=False, no_emulate=False) -> None:
    # Let argument override global 'emulate' setting
    # None if not overriden
    override_setting = True if force_emulate else (False if no_emulate else None)
    use_emulation = (
        bool(pwndbg.gdblib.config.emulate) if override_setting is None else override_setting
    )

    pc = pwndbg.gdblib.regs.pc

    instructions, index_of_pc = pwndbg.disasm.near(
        pc, 1, emulate=use_emulation, show_prev_insns=False, use_cache=False
    )

    if instructions:
        insn = instructions[0]
        print(repr(insn))
