from __future__ import annotations

import gdb
import user
from capstone.aarch64_const import AARCH64_INS_BL

import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.nearpc
import pwndbg.aglib.stack
import pwndbg.aglib.symbol
import pwndbg.dbg
from pwndbg.aglib.disasm.instruction import InstructionCondition

AARCH64_PREAMBLE = """
.text
.globl _start
_start:
"""

# The svc 0 is often the last instruction to be executed in these AArch64 tests and are placed in memory
# after all the other instructions. The bytes after it in memory (to fill the rest of the page) are typically filled with 0's.
# It was observed that compiling the program on different Linux distros even with the same Zig version might
# result in a couple of the bytes after svc being slightly different, resulting in the disassembly outputting
# slightly different instructions, like udf #0 or udf #23, depending on the source distro.
# To make this problem go away, the nops are added so that the disassembled instructions are consistent.
AARCH64_GRACEFUL_EXIT = """
mov x0, 0
mov x8, 93
svc 0
nop
nop
nop
nop
nop
nop
nop
nop
nop
"""

SIMPLE_FUNCTION = f"""
{AARCH64_PREAMBLE}

bl my_function
b end

my_function:
    ret

end:
{AARCH64_GRACEFUL_EXIT}
"""


def test_aarch64_branch_enhancement(qemu_assembly_run):
    """
    This test makes sures that the output of functions are correct in AArch64, and tests
    and case with AArch64 branches. BL and B instructions can be made conditional, and need
    manual handling to determine if they are not make conditional if there is no condition code.

    If the `b` instruction doesn't have a down arrow in the next line (the split), it means the detection to consider it an unconditional branch is broken.
    """
    qemu_assembly_run(SIMPLE_FUNCTION, "aarch64")

    instruction = pwndbg.aglib.disasm.disassembly.one_with_config()

    assert instruction.id == AARCH64_INS_BL
    assert instruction.call_like
    assert not instruction.is_conditional_jump
    assert instruction.is_unconditional_jump
    assert instruction.target_string == "my_function"

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010120 <_start>      bl     my_function                 <my_function>\n"
        "        x0:        0\n"
        "        x1:        0\n"
        "        x2:        0\n"
        "        x3:        0\n"
        " \n"
        "   0x1010124 <_start+4>    b      end                         <end>\n"
        "    ↓\n"
        "   0x101012c <end>         mov    x0, #0        X0 => 0\n"
        "   0x1010130 <end+4>       mov    x8, #0x5d     X8 => 0x5d\n"
        "   0x1010134 <end+8>       svc    #0\n"
        "   0x1010138 <end+12>      nop    \n"
        "   0x101013c <end+16>      nop    \n"
        "   0x1010140 <end+20>      nop    \n"
        "   0x1010144 <end+24>      nop    \n"
        "   0x1010148 <end+28>      nop    \n"
        "   0x101014c <end+32>      nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    # Now, ensure the `b` instruction is set correctly.
    gdb.execute("ni")

    instruction = pwndbg.aglib.disasm.disassembly.one_with_config()
    assert not instruction.is_conditional_jump
    assert instruction.is_unconditional_jump


EXIT_SYSCALL = f"""
{AARCH64_PREAMBLE}
{AARCH64_GRACEFUL_EXIT}
"""


def test_aarch64_syscall_annotation(qemu_assembly_run):
    """
    Validate that we have enriched syscalls correctly.
    """
    qemu_assembly_run(EXIT_SYSCALL, "aarch64")

    instructions = pwndbg.aglib.disasm.disassembly.near(
        address=pwndbg.aglib.regs.pc, instructions=3, emulate=True
    )[0]
    future_syscall_ins = instructions[2]

    assert future_syscall_ins.syscall == 93
    assert future_syscall_ins.syscall_name == "exit"

    # Verify that it shows up in the output
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010120 <_start>       mov    x0, #0            X0 => 0\n"
        "   0x1010124 <_start+4>     mov    x8, #0x5d         X8 => 0x5d\n"
        "   0x1010128 <_start+8>     svc    #0 <SYS_exit>\n"
        "   0x101012c <_start+12>    nop    \n"
        "   0x1010130 <_start+16>    nop    \n"
        "   0x1010134 <_start+20>    nop    \n"
        "   0x1010138 <_start+24>    nop    \n"
        "   0x101013c <_start+28>    nop    \n"
        "   0x1010140 <_start+32>    nop    \n"
        "   0x1010144 <_start+36>    nop    \n"
        "   0x1010148 <_start+40>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    gdb.execute("stepuntilasm svc")

    # Both for emulation and non-emulation, ensure a syscall at current PC gets enriched
    instructions = (
        pwndbg.aglib.disasm.disassembly.emulate_one(),
        pwndbg.aglib.disasm.disassembly.no_emulate_one(),
    )

    for i in instructions:
        assert i.syscall == 93
        assert i.syscall_name == "exit"


CONDITIONAL_JUMPS = f"""
{AARCH64_PREAMBLE}
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


def test_aarch64_conditional_jump_output(qemu_assembly_run):
    """
    Test that branches are resolved correctly, and make sure we have an annotation on the cmp instruction.
    """
    qemu_assembly_run(CONDITIONAL_JUMPS, "aarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010120 <_start>      mov    x2, #0xa     X2 => 0xa\n"
        "   0x1010124 <_start+4>    mov    x3, #0       X3 => 0\n"
        "   0x1010128 <_start+8>  ✔ cbz    x3, A                       <A>\n"
        "    ↓\n"
        "   0x1010130 <A>         ✔ cbnz   x2, B                       <B>\n"
        "    ↓\n"
        "   0x1010138 <B>         ✔ tbz    w2, #0, C                   <C>\n"
        "    ↓\n"
        "   0x1010140 <C>         ✔ tbnz   w2, #3, D                   <D>\n"
        "    ↓\n"
        "   0x1010148 <D>           cmp    x2, x3       0xa - 0x0     CPSR => 0x20000000 [ n z C v q pan il d a i f el:0 sp ]\n"
        "   0x101014c <D+4>         b.eq   E                           <E>\n"
        " \n"
        "   0x1010150 <D+8>         nop    \n"
        "   0x1010154 <E>         ✔ b.ne   F                           <F>\n"
        "    ↓\n"
        "   0x101015c <F>           mov    x0, #0       X0 => 0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


def test_aarch64_conditional_jumps(qemu_assembly_run):
    """
    Uses the same assembly has above, but ensures that the underlying manual determinations of the branches
    are correct, which is important for non-emulation.
    """
    qemu_assembly_run(CONDITIONAL_JUMPS, "aarch64")

    gdb.execute("stepuntilasm cbz")
    ins = pwndbg.aglib.disasm.disassembly.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.aglib.disasm.disassembly.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.aglib.disasm.disassembly.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.aglib.disasm.disassembly.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.aglib.disasm.disassembly.one_with_config()

    assert ins.condition == InstructionCondition.FALSE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.aglib.disasm.disassembly.one_with_config()

    assert ins.condition == InstructionCondition.TRUE


def test_conditional_jumps_no_emulate(qemu_assembly_run):
    gdb.execute("set emulate off")
    test_aarch64_conditional_jumps(qemu_assembly_run)


AARCH64_BINARY_OPERATIONS = f"""
{AARCH64_PREAMBLE}
mov x0, 7
mov x1, 563
add x2, x0, x1
sub x3, x1, x0
adds x2, x0, x1
subs x3, x1, x0
and x4, x0, x1
orr x5, x0, x1
eor x6, x0, x1
mul x10, x0, x1
udiv x11, x1, x0
"""


def test_aarch64_binary_operations(qemu_assembly_run):
    qemu_assembly_run(AARCH64_BINARY_OPERATIONS, "aarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010120 <_start>       mov    x0, #7          X0 => 7\n"
        "   0x1010124 <_start+4>     mov    x1, #0x233      X1 => 0x233\n"
        "   0x1010128 <_start+8>     add    x2, x0, x1      X2 => 0x23a (0x7 + 0x233)\n"
        "   0x101012c <_start+12>    sub    x3, x1, x0      X3 => 0x22c (0x233 - 0x7)\n"
        "   0x1010130 <_start+16>    adds   x2, x0, x1      X2 => 0x23a (0x7 + 0x233)\n"
        "   0x1010134 <_start+20>    subs   x3, x1, x0      X3 => 0x22c (0x233 - 0x7)\n"
        "   0x1010138 <_start+24>    and    x4, x0, x1      X4 => 3 (0x7 & 0x233)\n"
        "   0x101013c <_start+28>    orr    x5, x0, x1      X5 => 0x237 (0x7 | 0x233)\n"
        "   0x1010140 <_start+32>    eor    x6, x0, x1      X6 => 0x234 (0x7 ^ 0x233)\n"
        "   0x1010144 <_start+36>    mul    x10, x0, x1     X10 => 0xf65 (0x7 * 0x233)\n"
        "   0x1010148 <_start+40>    udiv   x11, x1, x0     X11 => 80 (0x233 / 0x7)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


# Nops are so that when we break at `stores`, the display doesn't have any previous instructions
AARCH64_STORES = f"""
{AARCH64_PREAMBLE}

ldr x0, =0x123456789ABCDEF0

nop
nop
nop
nop
nop
nop
nop
nop
nop

stores:
ldr x4, =value1
strb w0, [x4]

ldr x5, =value2
strh w0, [x5]

ldr x6, =value4
str w0, [x6]

ldr x7, =value8
str x0, [x7]

mov x8, 93
mov x0, 0
svc 0

    .data
value1: .byte 0
value2: .hword 0
value4: .word 0
value8: .quad 0

"""


def test_aarch64_store_instructions(qemu_assembly_run):
    qemu_assembly_run(AARCH64_STORES, "aarch64")

    gdb.execute("b stores")
    gdb.execute("c")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010180 <stores>       ldr    x4, stores+56     X4, [stores+56] => 0x10201d8 (value1) ◂— 0\n"
        "   0x1010184 <stores+4>     strb   w0, [x4]          [value1] <= 0xf0\n"
        "   0x1010188 <stores+8>     ldr    x5, stores+64     X5, [stores+64] => 0x10201d9 (value2) ◂— 0\n"
        "   0x101018c <stores+12>    strh   w0, [x5]          [value2] <= 0xdef0\n"
        "   0x1010190 <stores+16>    ldr    x6, stores+72     X6, [stores+72] => 0x10201db (value4) ◂— 0\n"
        "   0x1010194 <stores+20>    str    w0, [x6]          [value4] <= 0x9abcdef0\n"
        "   0x1010198 <stores+24>    ldr    x7, stores+80     X7, [stores+80] => 0x10201df (value8) ◂— 0\n"
        "   0x101019c <stores+28>    str    x0, [x7]          [value8] <= 0x123456789abcdef0\n"
        "   0x10101a0 <stores+32>    mov    x8, #0x5d         X8 => 0x5d\n"
        "   0x10101a4 <stores+36>    mov    x0, #0            X0 => 0\n"
        "   0x10101a8 <stores+40>    svc    #0 <SYS_exit>\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


AARCH64_LOADS = f"""
{AARCH64_PREAMBLE}


ldr x0, =0x123456789ABCDEF0
stores:
    ldr x4, =value1
    strb w0, [x4]

    ldr x5, =value2
    strh w0, [x5]

    ldr x6, =value4
    str w0, [x6]

    ldr x7, =value8
    str x0, [x7]

loads:

    ldrb w9, [x4]
    ldrsb w10, [x4]

    ldrh w12, [x5]
    ldrsh w13, [x5]

    ldr w15, [x6]
    ldrsw x16, [x6]

    ldr x18, [x6]

mov x8, 93
mov x0, 0
svc 0

    .data
value1: .byte 0
value2: .hword 0
value4: .word 0
value8: .quad 0
"""


def test_aarch64_load_instructions(qemu_assembly_run):
    """
    Test load operations, taking into account sign-extension.
    """
    qemu_assembly_run(AARCH64_LOADS, "aarch64")

    gdb.execute("b loads")
    gdb.execute("c")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x101017c <loads>       ldrb   w9, [x4]          W9, [value1] => 0xf0\n"
        "   0x1010180 <loads+4>     ldrsb  w10, [x4]         W10, [value1] => 0xfffffff0\n"
        "   0x1010184 <loads+8>     ldrh   w12, [x5]         W12, [value2] => 0xdef0\n"
        "   0x1010188 <loads+12>    ldrsh  w13, [x5]         W13, [value2] => 0xffffdef0\n"
        "   0x101018c <loads+16>    ldr    w15, [x6]         W15, [value4] => 0x9abcdef0\n"
        "   0x1010190 <loads+20>    ldrsw  x16, [x6]         X16, [value4] => 0xffffffff9abcdef0\n"
        "   0x1010194 <loads+24>    ldr    x18, [x6]         X18, [value4] => 0x9abcdef09abcdef0\n"
        "   0x1010198 <loads+28>    mov    x8, #0x5d         X8 => 0x5d\n"
        "   0x101019c <loads+32>    mov    x0, #0            X0 => 0\n"
        "   0x10101a0 <loads+36>    svc    #0 <SYS_exit>\n"
        "   0x10101a4 <loads+40>    udf    #0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


CPSR_REGISTER_TEST = f"""
{AARCH64_PREAMBLE}

mov x19, #8
cmn x19, #8
b.ne exit

nop
nop
nop
nop
nop

end:
exit:
{AARCH64_GRACEFUL_EXIT}
"""


def test_aarch64_write_cpsr_when_zero(qemu_assembly_run):
    """
    The purpose of this test is to ensure we writing our CPSR register to the Unicorn emulator always.

    We have an optimization to not write registers with the value zero to the emulator. This conflicts with the flags register.
    The CPSR register, by default, has the Z bit enabled, so the value is not 0. In this test, we do a comparison that sets the bit off,
    making CPSR have the value of zero. If we don't write 0 to this register explicitly emulator, Unicorn will take the "default" value which has the Z bit enabled.
    And therefore, the branch will be mispredicted.
    """

    qemu_assembly_run(CPSR_REGISTER_TEST, "aarch64")

    # Warm up the instruction cache so when we step forward, we remember the earlier instructions
    gdb.execute("context disasm")

    gdb.execute("si")
    gdb.execute("si")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        "   0x1010120 <_start>      mov    x19, #8     X19 => 8\n"
        "   0x1010124 <_start+4>    cmn    x19, #8     8 + 8     CPSR => 0x0 [ n z c v q pan il d a i f el:0 sp ]\n"
        " ► 0x1010128 <_start+8>  ✔ b.ne   exit                        <exit>\n"
        "    ↓\n"
        "   0x1010140 <exit>        mov    x0, #0            X0 => 0\n"
        "   0x1010144 <exit+4>      mov    x8, #0x5d         X8 => 0x5d\n"
        "   0x1010148 <exit+8>      svc    #0 <SYS_exit>\n"
        "   0x101014c <exit+12>     nop    \n"
        "   0x1010150 <exit+16>     nop    \n"
        "   0x1010154 <exit+20>     nop    \n"
        "   0x1010158 <exit+24>     nop    \n"
        "   0x101015c <exit+28>     nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


AARCH64_MEMORY_OPERAND_TEST = rf"""
{AARCH64_PREAMBLE}

LDR X1, =msg
LDR W0, [X1], #4
LDR W0, [X1, #4]
MOV X3, #8
LDR W4, [X1, X3]
LDR W5, [X1, #-4]
MOV X6, #-4
LDR W7, [X1, X6]

exit:
{AARCH64_GRACEFUL_EXIT}

data:
.data
msg:
    .asciz "ABCDEFGHIJKLMNOPQRSTUVWXYZ!"
"""


def test_aarch64_memory_operands(qemu_assembly_run):
    """
    Testing LDR instructions with interseting operands:
    - LDR a constant into a register
    - Post-index offset
    - Pre-index with constant/register
    - Pre-index with negated constants/register
    - Include shifts
    """

    qemu_assembly_run(AARCH64_MEMORY_OPERAND_TEST, "aarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010158 <_start>       ldr    x1, data          X1, [data] => 0x10201b0 (msg) ◂— 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!'\n"
        "   0x101015c <_start+4>     ldr    w0, [x1], #4      W0, [msg] => 0x44434241\n"
        "   0x1010160 <_start+8>     ldr    w0, [x1, #4]      W0, [msg+8] => 0x4c4b4a49\n"
        "   0x1010164 <_start+12>    mov    x3, #8            X3 => 8\n"
        "   0x1010168 <_start+16>    ldr    w4, [x1, x3]      W4, [msg+12] => 0x504f4e4d\n"
        "   0x101016c <_start+20>    ldur   w5, [x1, #-4]     W5, [msg] => 0x44434241\n"
        "   0x1010170 <_start+24>    mov    x6, #-4           X6 => 0xfffffffffffffffc\n"
        "   0x1010174 <_start+28>    ldr    w7, [x1, x6]      W7, [msg] => 0x44434241\n"
        "   0x1010178 <exit>         mov    x0, #0            X0 => 0\n"
        "   0x101017c <exit+4>       mov    x8, #0x5d         X8 => 0x5d\n"
        "   0x1010180 <exit+8>       svc    #0 <SYS_exit>\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


AARCH64_SHIFTS_AND_EXTENDS = f"""
{AARCH64_PREAMBLE}

mov X1, 1
mov X3, 8
ADD X0, X1, X1, LSL 2
ADD X0, X1, X3, LSR 2

MOV W2, 0xFFFFFFFF
ADD X0, X1, W2, SXTB
ADD X0, X1, W2, UXTB

ADD X0, X1, X2, ASR 2
ORR X0, xzr, X1, ror #2

SXTB X2, w2
ADD X0, X1, X2, ASR 2
"""


def test_aarch64_shifts_and_extends(qemu_assembly_run):
    """
    Ensure our logic in register shifts + extends are working correctly
    """
    qemu_assembly_run(AARCH64_SHIFTS_AND_EXTENDS, "aarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010120 <_start>       mov    x1, #1                  X1 => 1\n"
        "   0x1010124 <_start+4>     mov    x3, #8                  X3 => 8\n"
        "   0x1010128 <_start+8>     add    x0, x1, x1, lsl #2      X0 => 5 (1 + 4)\n"
        "   0x101012c <_start+12>    add    x0, x1, x3, lsr #2      X0 => 3 (1 + 2)\n"
        "   0x1010130 <_start+16>    mov    w2, #-1                 W2 => 0xffffffff\n"
        "   0x1010134 <_start+20>    add    x0, x1, w2, sxtb        X0 => 0 (0x1 + 0xffffffffffffffff)\n"
        "   0x1010138 <_start+24>    add    x0, x1, w2, uxtb        X0 => 0x100 (0x1 + 0xff)\n"
        "   0x101013c <_start+28>    add    x0, x1, x2, asr #2      X0 => 0x40000000 (0x1 + 0x3fffffff)\n"
        "   0x1010140 <_start+32>    orr    x0, xzr, x1, ror #2     X0 => 0x4000000000000000 (0x0 | 0x4000000000000000)\n"
        "   0x1010144 <_start+36>    sxtb   x2, w2\n"
        "   0x1010148 <_start+40>    add    x0, x1, x2, asr #2      X0 => 0 (0x1 + 0xffffffffffffffff)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


AARCH64_MEMORY_OPERAND_SHIFT = rf"""
{AARCH64_PREAMBLE}
LDR x2, =msg
ADD x2,x2,16
MOV w3, 0xffffffff
ldr x1, [x2, w3, sxtw]
ldr x1, [x2, w3, sxtw 3]
nop
.data
msg:
    .asciz "ABCDEFGHIJKLMNOPQRSTUVWXYZ!"
"""


def test_aarch64_shifts_and_extends_in_memory_operands(qemu_assembly_run):
    qemu_assembly_run(AARCH64_MEMORY_OPERAND_SHIFT, "aarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010158 <_start>       ldr    x2, _start+24             X2, [_start+24] => 0x1020178 (msg) ◂— 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!'\n"
        "   0x101015c <_start+4>     add    x2, x2, #0x10             X2 => 0x1020188 (msg+16) (0x1020178 + 0x10)\n"
        "   0x1010160 <_start+8>     mov    w3, #-1                   W3 => 0xffffffff\n"
        "   0x1010164 <_start+12>    ldr    x1, [x2, w3, sxtw]        X1, [msg+15] => 0x5756555453525150 ('PQRSTUVW')\n"
        "   0x1010168 <_start+16>    ldr    x1, [x2, w3, sxtw #3]     X1, [msg+8] => 0x504f4e4d4c4b4a49 ('IJKLMNOP')\n"
        "   0x101016c <_start+20>    nop    \n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


AARCH64_SHIFT_INSTRUCTIONS = f"""
{AARCH64_PREAMBLE}

MOV x0, #3
MOV x1, #0xF000
MOV x2, #0x1234
LSR x3, x1, #4
LSR x4, x1, x0
LSL x5, x4, #4
LSL x6, x4, x2
ASR x6, x4, #4
ASR x6, x4, x0
ROR x6, x4, #4
ROR x6, x4, x0
"""


def test_aarch64_shift_instructions(qemu_assembly_run):
    """
    Test annotations for shift instructions - the format of these has changed between Capstone versions.
    Special attention is paid to the shift-by-register amount
    - https://github.com/capstone-engine/capstone/issues/2631
    """
    qemu_assembly_run(AARCH64_SHIFT_INSTRUCTIONS, "aarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x1010120 <_start>       mov    x0, #3          X0 => 3\n"
        "   0x1010124 <_start+4>     mov    x1, #0xf000     X1 => 0xf000\n"
        "   0x1010128 <_start+8>     mov    x2, #0x1234     X2 => 0x1234\n"
        "   0x101012c <_start+12>    lsr    x3, x1, #4      X3 => 0xf00 (0xf000 >> 0x4)\n"
        "   0x1010130 <_start+16>    lsr    x4, x1, x0      X4 => 0x1e00\n"
        "   0x1010134 <_start+20>    lsl    x5, x4, #4      X5 => 0x1e000 (0x1e00 << 0x4)\n"
        "   0x1010138 <_start+24>    lsl    x6, x4, x2      X6 => 0xe000000000000000\n"
        "   0x101013c <_start+28>    asr    x6, x4, #4      X6 => 0x1e0 (0x1e00 >>s 0x4)\n"
        "   0x1010140 <_start+32>    asr    x6, x4, x0      X6 => 0x3c0\n"
        "   0x1010144 <_start+36>    ror    x6, x4, #4      X6 => 0x1e0 (0x1e00 >>r 0x4)\n"
        "   0x1010148 <_start+40>    ror    x6, x4, x0      X6 => 0x3c0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


REFERENCE_BINARY = user.binaries.get("reference-binary.aarch64.out")


def test_aarch64_reference(qemu_start_binary):
    qemu_start_binary(REFERENCE_BINARY, "aarch64")
    gdb.execute("break break_here")
    assert pwndbg.aglib.symbol.lookup_symbol("main") is not None
    gdb.execute("continue")

    gdb.execute("argv", to_string=True)
    assert gdb.execute("argc", to_string=True).strip() == "1"
    gdb.execute("auxv", to_string=True)
    assert (
        gdb.execute("cpsr", to_string=True, from_tty=False).strip()
        == "cpsr 0x0 [ n z c v q pan il d a i f el:0 sp ]"
    )
    gdb.execute("context", to_string=True)
    gdb.execute("hexdump", to_string=True)
    gdb.execute("telescope", to_string=True)

    # TODO: Broken
    gdb.execute("retaddr", to_string=True)

    # Broken
    gdb.execute("procinfo", to_string=True)

    # Broken
    gdb.execute("vmmap", to_string=True)

    gdb.execute("piebase", to_string=True)

    gdb.execute("nextret", to_string=True)


def test_memory_read_error_handling(qemu_assembly_run):
    """
    This test ensures that memory access errors are correctly handled and partial reads
    are attempted when possible. Specifically, it tests that the function can handle
    memory access failures at different address ranges and report the correct result.
    """
    qemu_assembly_run(SIMPLE_FUNCTION, "aarch64")

    # Find the first memory page where there is a gap after it
    stack_end_addr = -1
    page_prev = None
    for page in pwndbg.dbg.selected_inferior().vmmap().ranges():
        if page_prev is not None and page_prev.end != page.start:
            stack_end_addr = page_prev.end
            break
        page_prev = page

    assert stack_end_addr != -1, "Failed to find a memory page followed by a gap"

    result = pwndbg.dbg.selected_inferior().read_memory(stack_end_addr - 0xFF, 0xFF, partial=False)
    assert len(result) == 0xFF, f"Expected 0xff bytes, but got {len(result)}"

    try:
        pwndbg.dbg.selected_inferior().read_memory(stack_end_addr - 0xFE, 0xFF, partial=False)
        assert False, "Expected Error due to inaccessible memory address."
    except pwndbg.dbg_mod.Error:
        pass

    result = pwndbg.dbg.selected_inferior().read_memory(stack_end_addr - 0xFF, 0xFF, partial=True)
    assert len(result) == 0xFF, f"Expected 0xff bytes, but got {len(result)}"

    result = pwndbg.dbg.selected_inferior().read_memory(stack_end_addr - 0x10, 0xFF, partial=True)
    assert len(result) == 0x10, f"Expected 0x10 bytes, but got {len(result)}"

    result = pwndbg.dbg.selected_inferior().read_memory(stack_end_addr - 0x2, 0xFF, partial=True)
    assert len(result) == 0x2, f"Expected 0x2 bytes, but got {len(result)}"

    result = pwndbg.dbg.selected_inferior().read_memory(stack_end_addr - 0x1, 0xFF, partial=True)
    assert len(result) == 0x1, f"Expected 0x1 byte, but got {len(result)}"

    try:
        pwndbg.dbg.selected_inferior().read_memory(stack_end_addr - 0x0, 0xFF, partial=True)
        assert False, "Expected Error due to inaccessible memory address."
    except pwndbg.dbg_mod.Error:
        pass
