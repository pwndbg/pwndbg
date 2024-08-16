from __future__ import annotations

import gdb
from capstone.arm64_const import ARM64_INS_BL

import pwndbg.gdblib.disasm
import pwndbg.gdblib.nearpc
from pwndbg.gdblib.disasm.instruction import InstructionCondition

AARCH64_GRACEFUL_EXIT = """
mov x0, 0
mov x8, 93
svc 0
"""

SIMPLE_FUNCTION = f"""

bl my_function
b end

my_function:
    ret

end:
{AARCH64_GRACEFUL_EXIT}
"""


def test_syscall_annotation(qemu_assembly_run):
    """ """
    qemu_assembly_run(AARCH64_GRACEFUL_EXIT, "aarch64")

    instructions = pwndbg.gdblib.disasm.near(
        address=pwndbg.gdblib.regs.pc, instructions=3, emulate=True
    )[0]
    future_syscall_ins = instructions[2]

    assert future_syscall_ins.syscall == 93
    assert future_syscall_ins.syscall_name == "exit"

    gdb.execute("stepuntilasm svc")

    # Both for emulation and non-emulation, ensure a syscall at current PC gets enriched
    instructions = pwndbg.gdblib.disasm.emulate_one(), pwndbg.gdblib.disasm.no_emulate_one()

    for i in instructions:
        assert i.syscall == 93
        assert i.syscall_name == "exit"


def test_branch_enhancement(qemu_assembly_run):
    qemu_assembly_run(SIMPLE_FUNCTION, "aarch64")

    instruction = pwndbg.gdblib.disasm.one_with_config()

    assert instruction.id == ARM64_INS_BL
    assert instruction.call_like
    assert not instruction.is_conditional_jump
    assert instruction.is_unconditional_jump
    assert instruction.target_string == "my_function"


CONDITIONAL_JUMPS = f"""
mov x2, 0b1010
mov x3, 0

cbz x3, A
nop

A:
cbnz x2, B
nop

B:
tbz x2, #0, C
nop

C:
tbnz x2, #3, D
nop

D:
cmp x2, x3
b.eq E
nop

E:
b.ne F
nop

F:
{AARCH64_GRACEFUL_EXIT}
"""


def test_conditional_jumps(qemu_assembly_run):
    qemu_assembly_run(CONDITIONAL_JUMPS, "aarch64")

    gdb.execute("stepuntilasm cbz")
    ins = pwndbg.gdblib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.gdblib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.gdblib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.gdblib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.gdblib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.FALSE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.gdblib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE


def test_conditional_jumps_no_emulate(qemu_assembly_run):
    gdb.execute("set emulate off")
    test_conditional_jumps(qemu_assembly_run)
