from __future__ import annotations

import os

import pwndbg.aglib.disasm.disassembly
import pwndbg.arguments
from pwndbg.aglib.disasm.instruction import PwndbgInstruction

BINARIES_PATH = os.environ.get("TEST_BINARIES_ROOT")


def get_binary(name: str) -> str:
    return os.path.join(BINARIES_PATH, name)


def instruction_at_pc() -> PwndbgInstruction:
    ins = pwndbg.aglib.disasm.disassembly.one()
    assert ins is not None
    return ins


def args_at_pc() -> list[tuple[str, int]]:
    """
    Return the (name, value) of the arguments shown for the call or syscall instruction at PC
    """
    return [(arg.name, value) for arg, value in pwndbg.arguments.get(instruction_at_pc())]


def syscalls_at_pc() -> list[tuple[int | None, str | None]]:
    """
    Return the (syscall number, syscall name) the instruction at PC is enriched with,
    both with and without emulation
    """
    result = []
    for ins in (
        pwndbg.aglib.disasm.disassembly.emulate_one(),
        pwndbg.aglib.disasm.disassembly.no_emulate_one(),
    ):
        assert ins is not None
        result.append((ins.syscall, ins.syscall_name))
    return result
