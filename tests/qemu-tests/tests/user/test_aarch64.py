from __future__ import annotations

import gdb
import user
from capstone.arm64_const import ARM64_INS_BL

import pwndbg.aglib.disasm
import pwndbg.gdblib.nearpc
import pwndbg.gdblib.symbol
from pwndbg.aglib.disasm.instruction import InstructionCondition

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


def test_aarch64_branch_enhancement(qemu_assembly_run):
    """
    This test makes sures that the output of functions are correct in AArch64, and tests
    and case with AArch64 branches. BL and B instructions can be made conditional, and need
    manual handling to determine if they are not make conditional if there is no condition code.

    If the `b` instruction doesn't have a down arrow in the next line (the split), it means the detection to consider it an unconditional branch is broken.
    """
    qemu_assembly_run(SIMPLE_FUNCTION, "aarch64")

    instruction = pwndbg.aglib.disasm.one_with_config()

    assert instruction.id == ARM64_INS_BL
    assert instruction.call_like
    assert not instruction.is_conditional_jump
    assert instruction.is_unconditional_jump
    assert instruction.target_string == "my_function"

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x10000000 <_start>      bl     #my_function                <my_function>\n"
        "        x0:        0\n"
        "        x1:        0\n"
        "        x2:        0\n"
        "        x3:        0\n"
        " \n"
        "   0x10000004 <_start+4>    b      #end                        <end>\n"
        "    ↓\n"
        "   0x1000000c <end>         mov    x0, #0        X0 => 0\n"
        "   0x10000010 <end+4>       mov    x8, #0x5d     X8 => 0x5d\n"
        "   0x10000014 <end+8>       svc    #0\n"
        "   0x10000018               udf    #0\n"
        "   0x1000001c               udf    #0\n"
        "   0x10000020               udf    #0\n"
        "   0x10000024               udf    #0\n"
        "   0x10000028               udf    #0\n"
        "   0x1000002c               udf    #0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    # Now, ensure the `b` instruction is set correctly.
    gdb.execute("si")

    instruction = pwndbg.aglib.disasm.one_with_config()
    assert not instruction.is_conditional_jump
    assert instruction.is_unconditional_jump


def test_aarch64_syscall_annotation(qemu_assembly_run):
    """
    Validate that we have enriched syscalls correctly.
    """
    qemu_assembly_run(AARCH64_GRACEFUL_EXIT, "aarch64")

    instructions = pwndbg.aglib.disasm.near(
        address=pwndbg.gdblib.regs.pc, instructions=3, emulate=True
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
        " ► 0x10000000 <_start>      mov    x0, #0            X0 => 0\n"
        "   0x10000004 <_start+4>    mov    x8, #0x5d         X8 => 0x5d\n"
        "   0x10000008 <_start+8>    svc    #0 <SYS_exit>\n"
        "   0x1000000c               udf    #0\n"
        "   0x10000010               udf    #0\n"
        "   0x10000014               udf    #0\n"
        "   0x10000018               udf    #0\n"
        "   0x1000001c               udf    #0\n"
        "   0x10000020               udf    #0\n"
        "   0x10000024               udf    #0\n"
        "   0x10000028               udf    #0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    gdb.execute("stepuntilasm svc")

    # Both for emulation and non-emulation, ensure a syscall at current PC gets enriched
    instructions = pwndbg.aglib.disasm.emulate_one(), pwndbg.aglib.disasm.no_emulate_one()

    for i in instructions:
        assert i.syscall == 93
        assert i.syscall_name == "exit"


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
        " ► 0x10000000 <_start>      mov    x2, #0xa     X2 => 0xa\n"
        "   0x10000004 <_start+4>    mov    x3, #0       X3 => 0\n"
        "   0x10000008 <_start+8>  ✔ cbz    x3, #A                      <A>\n"
        "    ↓\n"
        "   0x10000010 <A>         ✔ cbnz   x2, #B                      <B>\n"
        "    ↓\n"
        "   0x10000018 <B>         ✔ tbz    w2, #0, #C                  <C>\n"
        "    ↓\n"
        "   0x10000020 <C>         ✔ tbnz   w2, #3, #D                  <D>\n"
        "    ↓\n"
        "   0x10000028 <D>           cmp    x2, x3       0xa - 0x0     CPSR => 0x20000000 [ n z C v q pan il d a i f el:0 sp ]\n"
        "   0x1000002c <D+4>         b.eq   #E                          <E>\n"
        " \n"
        "   0x10000030 <D+8>         nop    \n"
        "   0x10000034 <E>         ✔ b.ne   #F                          <F>\n"
        "    ↓\n"
        "   0x1000003c <F>           mov    x0, #0       X0 => 0\n"
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
    ins = pwndbg.aglib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.aglib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.aglib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    ins = pwndbg.aglib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.aglib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.FALSE

    gdb.execute("si")
    gdb.execute("si")

    ins = pwndbg.aglib.disasm.one_with_config()

    assert ins.condition == InstructionCondition.TRUE


def test_conditional_jumps_no_emulate(qemu_assembly_run):
    gdb.execute("set emulate off")
    test_aarch64_conditional_jumps(qemu_assembly_run)


AARCH64_ASSEMBLY = """
mov x0, 7
mov x1, 563

add x2, x0, x1
sub x3, x1, x0
and x4, x0, x1
orr x5, x0, x1
eor x6, x0, x1
lsl x7, x0, 2
lsr x8, x1, 2
mul x10, x0, x1
udiv x11, x1, x0

"""


def test_aarch64_binary_operations(qemu_assembly_run):
    qemu_assembly_run(AARCH64_ASSEMBLY, "aarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / aarch64 / set emulate on ]──────────────────────\n"
        " ► 0x10000000 <_start>       mov    x0, #7          X0 => 7\n"
        "   0x10000004 <_start+4>     mov    x1, #0x233      X1 => 0x233\n"
        "   0x10000008 <_start+8>     add    x2, x0, x1      X2 => 0x23a (0x7 + 0x233)\n"
        "   0x1000000c <_start+12>    sub    x3, x1, x0      X3 => 0x22c (0x233 - 0x7)\n"
        "   0x10000010 <_start+16>    and    x4, x0, x1      X4 => 3 (0x7 & 0x233)\n"
        "   0x10000014 <_start+20>    orr    x5, x0, x1      X5 => 0x237 (0x7 & 0x233)\n"
        "   0x10000018 <_start+24>    eor    x6, x0, x1      X6 => 0x234 (0x7 ^ 0x233)\n"
        "   0x1000001c <_start+28>    lsl    x7, x0, #2      X7 => 28 (7 << 2)\n"
        "   0x10000020 <_start+32>    lsr    x8, x1, #2      X8 => 140 (0x233 >> 0x2)\n"
        "   0x10000024 <_start+36>    mul    x10, x0, x1     X10 => 0xf65 (0x7 * 0x233)\n"
        "   0x10000028 <_start+40>    udiv   x11, x1, x0     X11 => 80 (0x233 / 0x7)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


# Nops are so that when we break at `stores`, the display doesn't have any previous instructions
AARCH64_STORES = """

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
        " ► 0x10000028 <stores>       ldr    x4, #stores+56     X4, 0x10000060 => 0x4010e8 (value1) ◂— 0\n"
        "   0x1000002c <stores+4>     strb   w0, [x4]           [value1] => 0xf0\n"
        "   0x10000030 <stores+8>     ldr    x5, #stores+64     X5, 0x10000068 => 0x4010e9 (value2) ◂— 0\n"
        "   0x10000034 <stores+12>    strh   w0, [x5]           [value2] => 0xdef0\n"
        "   0x10000038 <stores+16>    ldr    x6, #stores+72     X6, 0x10000070 => 0x4010eb (value4) ◂— 0\n"
        "   0x1000003c <stores+20>    str    w0, [x6]           [value4] => 0x9abcdef0\n"
        "   0x10000040 <stores+24>    ldr    x7, #stores+80     X7, 0x10000078 => 0x4010ef (value8) ◂— 0\n"
        "   0x10000044 <stores+28>    str    x0, [x7]           [value8] => 0x123456789abcdef0\n"
        "   0x10000048 <stores+32>    mov    x8, #0x5d          X8 => 0x5d\n"
        "   0x1000004c <stores+36>    mov    x0, #0             X0 => 0\n"
        "   0x10000050 <stores+40>    svc    #0 <SYS_exit>\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


AARCH64_LOADS = """

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
        " ► 0x10000024 <loads>       ldrb   w9, [x4]          W9, [value1] => 0xf0\n"
        "   0x10000028 <loads+4>     ldrsb  w10, [x4]         W10, [value1] => 0xfffffff0\n"
        "   0x1000002c <loads+8>     ldrh   w12, [x5]         W12, [value2] => 0xdef0\n"
        "   0x10000030 <loads+12>    ldrsh  w13, [x5]         W13, [value2] => 0xffffdef0\n"
        "   0x10000034 <loads+16>    ldr    w15, [x6]         W15, [value4] => 0x9abcdef0\n"
        "   0x10000038 <loads+20>    ldrsw  x16, [x6]         X16, [value4] => 0xffffffff9abcdef0\n"
        "   0x1000003c <loads+24>    ldr    x18, [x6]         X18, [value4] => 0x9abcdef09abcdef0\n"
        "   0x10000040 <loads+28>    mov    x8, #0x5d         X8 => 0x5d\n"
        "   0x10000044 <loads+32>    mov    x0, #0            X0 => 0\n"
        "   0x10000048 <loads+36>    svc    #0 <SYS_exit>\n"
        "   0x1000004c <loads+40>    udf    #0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


REFERENCE_BINARY = user.binaries.get("reference-binary.aarch64.out")


def test_aarch64_reference(qemu_start_binary):
    qemu_start_binary(REFERENCE_BINARY, "aarch64")
    gdb.execute("break break_here")
    assert pwndbg.gdblib.symbol.address("main") is not None
    gdb.execute("continue")

    gdb.execute("argv", to_string=True)
    assert gdb.execute("argc", to_string=True).strip() == "1"
    gdb.execute("auxv", to_string=True)
    assert (
        gdb.execute("cpsr", to_string=True, from_tty=False).strip()
        == "cpsr 0x60000000 [ n Z C v q pan il d a i f el:0 sp ]"
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
