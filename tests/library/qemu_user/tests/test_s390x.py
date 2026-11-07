from __future__ import annotations

import gdb

import pwndbg.aglib.disasm.disassembly
import pwndbg.arguments

S390X_CALL_AND_SYSCALLS = """
.text
.globl _start
_start:
    lghi %r2, 1
    lghi %r3, 2
    lghi %r4, 3
    brasl %r14, write
write_syscall:
    svc 4
exit_seq:
    lghi %r2, 0
    lghi %r1, 1
    svc 0
    nopr
    nopr

write:
    br %r14
"""


def break_at(label: str) -> None:
    gdb.execute(f"break *{label}")
    gdb.execute("continue")


def args_at_pc() -> list[tuple[str, int]]:
    args = pwndbg.arguments.get(pwndbg.aglib.disasm.disassembly.one())
    return [(arg.name, value) for arg, value in args]


def test_s390x_function_arguments(qemu_assembly_run):
    qemu_assembly_run(S390X_CALL_AND_SYSCALLS, "s390x")

    gdb.execute("stepuntilasm brasl")

    assert args_at_pc() == [("fd", 1), ("buf", 2), ("n", 3)]


def test_s390x_syscall_number_in_immediate(qemu_assembly_run):
    """
    `svc N` with N != 0 encodes the syscall number in the instruction itself.
    """
    qemu_assembly_run(S390X_CALL_AND_SYSCALLS, "s390x")

    break_at("write_syscall")

    for ins in (
        pwndbg.aglib.disasm.disassembly.emulate_one(),
        pwndbg.aglib.disasm.disassembly.no_emulate_one(),
    ):
        assert ins.syscall == 4
        assert ins.syscall_name == "write"

    assert args_at_pc() == [("fd", 1), ("buf", 2), ("n", 3)]


def test_s390x_syscall_number_in_r1(qemu_assembly_run):
    """
    `svc 0` takes the syscall number from r1.
    """
    qemu_assembly_run(S390X_CALL_AND_SYSCALLS, "s390x")

    break_at("exit_seq")

    # With emulation, the syscall number is known before r1 is set
    future_syscall_ins = pwndbg.aglib.disasm.disassembly.near(
        address=pwndbg.aglib.regs.pc, forward_count=3, emulate=True
    )[0][2]
    assert future_syscall_ins.syscall == 1
    assert future_syscall_ins.syscall_name == "exit"

    gdb.execute("stepuntilasm svc")

    for ins in (
        pwndbg.aglib.disasm.disassembly.emulate_one(),
        pwndbg.aglib.disasm.disassembly.no_emulate_one(),
    ):
        assert ins.syscall == 1
        assert ins.syscall_name == "exit"

    assert args_at_pc() == [("status", 0)]
