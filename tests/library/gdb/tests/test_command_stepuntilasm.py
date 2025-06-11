from __future__ import annotations

import gdb

import pwndbg.aglib.regs
import tests

STEPUNTILASM_X64_BINARY = tests.binaries.get("stepuntilasm_x64.out")


def test_command_untilasm_x64(start_binary):
    start_binary(STEPUNTILASM_X64_BINARY)
    gdb.execute("break break_here")
    gdb.execute("run")

    run_and_verify("stop1", "nop")
    run_and_verify("stop2", "xor rax, rax")
    run_and_verify("stop3", "mov qword ptr [rax], 0x20")
    run_and_verify("stop4", "mov dword ptr [rax+4], 0x20")


def run_and_verify(stop_label, asm):
    gdb.execute(f"stepuntilasm {asm}")
    address = int(gdb.parse_and_eval(f"&{stop_label}"))
    assert pwndbg.aglib.regs.pc == address
