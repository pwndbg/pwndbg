from __future__ import annotations

from collections.abc import Callable

import gdb
import pytest

import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.color

GUARD_32 = 0x11223300
GUARD_64 = 0x1122334455667700

CANARY_PROGRAMS = {
    "arm": (
        GUARD_32,
        """
.text
.globl _start
_start:
    ldr r0, =__stack_chk_guard
    ldr r0, [r0]
    push {r0}
    nop
check:
    nop
    mov r0, #0
    mov r7, #1
    svc 0
.ltorg

.data
.balign 4
.globl __stack_chk_guard
__stack_chk_guard:
    .word 0x11223300
""",
    ),
    "mipsel32": (
        GUARD_32,
        """
.set noreorder
.text
.globl __start
__start:
    lui $t0, %hi(__stack_chk_guard)
    lw $t1, %lo(__stack_chk_guard)($t0)
    addiu $sp, $sp, -16
    sw $t1, 0($sp)
    nop
check:
    nop
    li $a0, 0
    li $v0, 4001
    syscall
    nop

.data
.balign 4
.globl __stack_chk_guard
__stack_chk_guard:
    .word 0x11223300
""",
    ),
    "riscv64": (
        GUARD_64,
        """
.text
.globl _start
_start:
    la t0, __stack_chk_guard
    ld t1, 0(t0)
    addi sp, sp, -16
    sd t1, 0(sp)
    nop
check:
    nop
    li a0, 0
    li a7, 93
    ecall

.data
.balign 8
.globl __stack_chk_guard
__stack_chk_guard:
    .quad 0x1122334455667700
""",
    ),
    "loongarch64": (
        GUARD_64,
        """
.text
.globl _start
_start:
    la.pcrel $t0, __stack_chk_guard
    ld.d $t1, $t0, 0
    addi.d $sp, $sp, -16
    st.d $t1, $sp, 0
    nop
check:
    nop
    li.d $a0, 0
    li.d $a7, 93
    syscall 0

.data
.balign 8
.globl __stack_chk_guard
__stack_chk_guard:
    .quad 0x1122334455667700
""",
    ),
}


@pytest.mark.parametrize("arch", CANARY_PROGRAMS.keys())
def test_canary_from_stack_chk_guard(
    qemu_assembly_run: Callable[[str, str], None], arch: str
) -> None:
    guard, asm = CANARY_PROGRAMS[arch]
    qemu_assembly_run(asm, arch)

    gdb.execute("b check")
    gdb.execute("c")

    guard_addr = pwndbg.aglib.symbol.lookup_symbol_addr("__stack_chk_guard")
    assert guard_addr is not None
    assert pwndbg.aglib.memory.read_pointer_width(guard_addr) == guard

    out = pwndbg.color.strip(gdb.execute("canary", to_string=True))
    assert f"__stack_chk_guard @ {guard_addr:#x}" in out
    assert f"Canary     = {guard:#x}" in out
    assert "Found valid canary" in out
