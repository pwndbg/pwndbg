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


def test_compile_and_run(qemu_assembly_run):
    qemu_assembly_run(SIMPLE_FUNCTION, "aarch64")

    instruction = pwndbg.gdblib.disasm.emulate_one()

    # Some random tests
    assert instruction.id == ARM64_INS_BL
    assert instruction.call_like
    assert instruction.is_unconditional_jump
    assert instruction.target_string == "my_function"

    gdb.execute("si")
    gdb.execute("stepuntilasm svc")

    instruction = pwndbg.gdblib.disasm.emulate_one()

    assert instruction.syscall == 93
    assert instruction.syscall_name == "exit"


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

    gdb.execute("si")
    gdb.execute("stepuntilasm cbz")
    ins = pwndbg.gdblib.disasm.emulate_one()
    ins_no_emulate = pwndbg.gdblib.disasm.one()

    assert ins.condition == InstructionCondition.TRUE
    assert ins_no_emulate.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.gdblib.disasm.emulate_one()
    ins_no_emulate = pwndbg.gdblib.disasm.one()

    assert ins.condition == InstructionCondition.TRUE
    assert ins_no_emulate.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.gdblib.disasm.emulate_one()
    ins_no_emulate = pwndbg.gdblib.disasm.one()

    assert ins.condition == InstructionCondition.TRUE
    assert ins_no_emulate.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.gdblib.disasm.emulate_one()
    ins_no_emulate = pwndbg.gdblib.disasm.one()

    assert ins.condition == InstructionCondition.TRUE
    assert ins_no_emulate.condition == InstructionCondition.TRUE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.gdblib.disasm.emulate_one()
    ins_no_emulate = pwndbg.gdblib.disasm.one()

    assert ins.condition == InstructionCondition.FALSE
    assert ins_no_emulate.condition == InstructionCondition.FALSE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.gdblib.disasm.emulate_one()
    ins_no_emulate = pwndbg.gdblib.disasm.one()

    assert ins.condition == InstructionCondition.TRUE
    assert ins_no_emulate.condition == InstructionCondition.TRUE
