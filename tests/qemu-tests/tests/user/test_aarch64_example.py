from __future__ import annotations

import gdb
from capstone.arm64_const import ARM64_INS_BL

import pwndbg.gdblib.disasm

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

    # TODO: cleaner API to get and enhance one instruction WITH emulation
    instruction = pwndbg.gdblib.disasm.near(pwndbg.gdblib.regs.pc)[0][0]

    # Some random tests
    assert instruction.id == ARM64_INS_BL
    assert instruction.call_like
    assert instruction.is_unconditional_jump
    assert instruction.target_string == "my_function"

    gdb.execute("si")
    gdb.execute("stepuntilasm svc")

    instruction = pwndbg.gdblib.disasm.near(pwndbg.gdblib.regs.pc, show_prev_insns=False)[0][0]

    print(instruction)

    assert instruction.syscall == 93
    assert instruction.syscall_name == "exit"


def test2(qemu_assembly_run):
    test_compile_and_run(qemu_assembly_run)


def test3(qemu_assembly_run):
    test_compile_and_run(qemu_assembly_run)


def test4(qemu_assembly_run):
    test_compile_and_run(qemu_assembly_run)


def test5(qemu_assembly_run):
    test_compile_and_run(qemu_assembly_run)
