from __future__ import annotations

from collections.abc import Callable

import gdb

import pwndbg.aglib.disasm.disassembly

from . import args_at_pc
from . import instruction_at_pc
from . import syscalls_at_pc

S390X_CALL_AND_SYSCALLS = """
.text
.globl _start
_start:
    lghi %r2, 1
    lghi %r3, 2
    lghi %r4, 3
    brasl %r14, write
    lghi %r5, 0
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


def test_s390x_function_arguments(qemu_assembly_run: Callable[..., None]) -> None:
    qemu_assembly_run(S390X_CALL_AND_SYSCALLS, "s390x")

    gdb.execute("stepuntilasm brasl")

    assert args_at_pc() == [("fd", 1), ("buf", 2), ("n", 3)]


def test_s390x_syscall_number_in_immediate(qemu_assembly_run: Callable[..., None]) -> None:
    """
    `svc N` with N != 0 encodes the syscall number in the instruction itself.
    """
    qemu_assembly_run(S390X_CALL_AND_SYSCALLS, "s390x")

    break_at("write_syscall")

    assert syscalls_at_pc() == [(4, "write"), (4, "write")]
    assert args_at_pc() == [("fd", 1), ("buf", 2), ("n", 3)]


def test_s390x_syscall_number_in_r1(qemu_assembly_run: Callable[..., None]) -> None:
    """
    `svc 0` takes the syscall number from r1.
    """
    qemu_assembly_run(S390X_CALL_AND_SYSCALLS, "s390x")

    break_at("exit_seq")

    # With emulation, the syscall number is known before r1 is set
    future_syscall_ins = pwndbg.aglib.disasm.disassembly.near(
        address=instruction_at_pc().address, forward_count=3, emulate=True
    )[0][2]
    assert future_syscall_ins.mnemonic == "svc"
    assert future_syscall_ins.syscall == 1
    assert future_syscall_ins.syscall_name == "exit"

    gdb.execute("stepuntilasm svc")

    assert syscalls_at_pc() == [(1, "exit"), (1, "exit")]
    assert args_at_pc() == [("status", 0)]


def test_s390x_stepsyscall_number_in_immediate(qemu_assembly_run: Callable[..., None]) -> None:
    """
    `stepsyscall <name>` must match `svc N`, where r1 does not hold the syscall number.
    """
    qemu_assembly_run(S390X_CALL_AND_SYSCALLS, "s390x")

    gdb.execute("stepsyscall write")

    assert instruction_at_pc().syscall_name == "write"

    gdb.execute("stepsyscall exit")

    assert instruction_at_pc().syscall_name == "exit"
