from __future__ import annotations

import gdb

import pwndbg.color

ARM_PREAMBLE = """
.text
.globl _start
_start:
"""

ARM_GRACEFUL_EXIT = """
mov r0, 0
mov r7, 0xf8
swi #0
"""

ARM_BRANCHES = f"""
{ARM_PREAMBLE}
mov r2, #5
mov r1, #10
cmp r0, r1
bne not_equal
nop
nop
not_equal:
    mov r3, #1
    cmp r1, r3
    bgt greater
nop
nop
greater:
    cmp r3, r1
    bls end
nop
nop
end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_simple_branch(qemu_assembly_run):
    """
    Simple test to ensure branches are being followed correctly and that they are remembered when stepping past them
    """
    qemu_assembly_run(ARM_BRANCHES, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>         mov    r2, #5       R2 => 5\n"
        "   0x200b8 <_start+4>       mov    r1, #0xa     R1 => 0xa\n"
        "   0x200bc <_start+8>       cmp    r0, r1       0x0 - 0xa     CPSR => 0x80000010 [ N z c v q j t e a i f ]\n"
        "   0x200c0 <_start+12>    ✔ bne    not_equal                   <not_equal>\n"
        "    ↓\n"
        "   0x200cc <not_equal>      mov    r3, #1       R3 => 1\n"
        "   0x200d0 <not_equal+4>    cmp    r1, r3       0xa - 0x1     CPSR => 0x20000010 [ n z C v q j t e a i f ]\n"
        "   0x200d4 <not_equal+8>  ✔ bgt    greater                     <greater>\n"
        "    ↓\n"
        "   0x200e0 <greater>        cmp    r3, r1       0x1 - 0xa     CPSR => 0x80000010 [ N z c v q j t e a i f ]\n"
        "   0x200e4 <greater+4>    ✔ bls    end                         <end>\n"
        "    ↓\n"
        "   0x200f0 <end>            mov    r0, #0        R0 => 0\n"
        "   0x200f4 <end+4>          mov    r7, #0xf8     R7 => 0xf8\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    gdb.execute("si 8")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        "   0x200c0 <_start+12>    ✔ bne    not_equal                   <not_equal>\n"
        "    ↓\n"
        "   0x200cc <not_equal>      mov    r3, #1       R3 => 1\n"
        "   0x200d0 <not_equal+4>    cmp    r1, r3       0xa - 0x1     CPSR => 0x20000010 [ n z C v q j t e a i f ]\n"
        "   0x200d4 <not_equal+8>  ✔ bgt    greater                     <greater>\n"
        "    ↓\n"
        "   0x200e0 <greater>        cmp    r3, r1       0x1 - 0xa     CPSR => 0x80000010 [ N z c v q j t e a i f ]\n"
        " ► 0x200e4 <greater+4>    ✔ bls    end                         <end>\n"
        "    ↓\n"
        "   0x200f0 <end>            mov    r0, #0                  R0 => 0\n"
        "   0x200f4 <end+4>          mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x200f8 <end+8>          svc    #0 <SYS_exit_group>\n"
        "   0x200fc                  andeq  r3, r0, r1, asr #32\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_INTERWORKING_BRANCH = f"""
{ARM_PREAMBLE}
add r0, pc, #1
bx r0

.THUMB
mov r2, #4
add r2, r2, r0

end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_interworking_branch(qemu_assembly_run):
    """
    This test checks that we properly recognize a transition from Arm to Thumb mode.
    This requires Capstone to be synced with Unicorn, and for Unicorn to properly execute Thumb instructions.

    The code starts in Arm mode, then transitions to Thumb mode.
    If this breaks, it is likely that something has stopped Unicorn from correctly running Thumb mode instructions.

    Additionally, the lowest bit of the target must always be 0 - although interworking branches that transition to Thumb mode
    appear to write a 1 to the lowest bit, in the hardware the bit is directed to the Thumb bit in the CPSR flags register.
    See: https://github.com/pwndbg/pwndbg/pull/2292
    """
    qemu_assembly_run(ARM_INTERWORKING_BRANCH, "arm")

    dis = gdb.execute("emulate 3", to_string=True)

    expected = (
        " ► 0x200b4 <_start>       add    r0, pc, #1     R0 => 0x200bd (_start+9) (0x200bc + 0x1)\n"
        "   0x200b8 <_start+4>     bx     r0                          <_start+8>\n"
        "    ↓\n"
        "   0x200bc <_start+8>     mov.w  r2, #4                  R2 => 4\n"
        "   0x200c0 <_start+12>    add    r2, r0                  R2 => 0x200c1 (_start+13) (0x4 + 0x200bd)\n"
        "   0x200c2 <end>          mov.w  r0, #0                  R0 => 0\n"
        "   0x200c6 <end+4>        mov.w  r7, #0xf8               R7 => 0xf8\n"
        "   0x200ca <end+8>        svc    #0 <SYS_exit_group>\n"
    )

    assert dis == expected

    # Make sure the transition is remembered

    gdb.execute("si 2")

    dis = gdb.execute("emulate 3", to_string=True)

    expected = (
        "   0x200b4 <_start>       add    r0, pc, #1     R0 => 0x200bd (_start+9) (0x200bc + 0x1)\n"
        "   0x200b8 <_start+4>     bx     r0                          <_start+8>\n"
        "    ↓\n"
        " ► 0x200bc <_start+8>     mov.w  r2, #4                  R2 => 4\n"
        "   0x200c0 <_start+12>    add    r2, r0                  R2 => 0x200c1 (_start+13) (0x4 + 0x200bd)\n"
        "   0x200c2 <end>          mov.w  r0, #0                  R0 => 0\n"
        "   0x200c6 <end+4>        mov.w  r7, #0xf8               R7 => 0xf8\n"
        "   0x200ca <end+8>        svc    #0 <SYS_exit_group>\n"
    )

    assert dis == expected


ARM_IMPLICIT_BRANCH = f"""
{ARM_PREAMBLE}
ldr     R1, =_target
ADD PC, R1, #1

nop

.THUMB
_target:
mov r1, #2
mov r2, #4
mov r6, #3
add r1, r2, r3
sub r4, r5, r6
orr r6, r6, r5
and r2, r2, r5
eor r1, r2, r1
lsr r3, #4
"""


def test_arm_implicit_branch(qemu_assembly_run):
    """
    In Arm, many general-purpose instructions can target the PC as the destination register, particularly while changing between Arm/Thumb mode

    For example, the `add` and `sub` instructions can be used to directory write to the PC, forming a branch.

    This test contains a "add" instruction that causes the PC to change. We want there to be a <target> displayed, and a space after it in the disasm
    """

    qemu_assembly_run(ARM_IMPLICIT_BRANCH, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>        ldr    r1, [pc, #0x28]     R1, [_target+36] => 0x200c0 (_target) ◂— 0x102f04f\n"
        "   0x200b8 <_start+4>      add    pc, r1, #1                  <_target>\n"
        "    ↓\n"
        "   0x200c0 <_target>       mov.w  r1, #2              R1 => 2\n"
        "   0x200c4 <_target+4>     mov.w  r2, #4              R2 => 4\n"
        "   0x200c8 <_target+8>     mov.w  r6, #3              R6 => 3\n"
        "   0x200cc <_target+12>    add.w  r1, r2, r3          R1 => 4 (4 + 0)\n"
        "   0x200d0 <_target+16>    sub.w  r4, r5, r6          R4 => 0xfffffffd (0 - 3)\n"
        "   0x200d4 <_target+20>    orr.w  r6, r6, r5          R6 => 3 (3 | 0)\n"
        "   0x200d8 <_target+24>    and.w  r2, r2, r5          R2 => 0 (4 & 0)\n"
        "   0x200dc <_target+28>    eor.w  r1, r2, r1          R1 => 4 (0 ^ 4)\n"
        "   0x200e0 <_target+32>    lsr.w  r3, r3, #4          R3 => 0 (0 >> 4)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_IMPLICIT_BRANCH_NEXT_INSTRUCTION = f"""
{ARM_PREAMBLE}
ldr     R1, =_target
ADD PC, R1, #1

.THUMB
_target:
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
add r1, r2, r3
"""


def test_arm_implicit_branch_next_instruction(qemu_assembly_run):
    """
    This is near identical to the test above, with a minor change that makes it tricky.

    The branch target of the add instruction is the next instruction in memory. This requires special detection for this case, as we typically
    detect branches based on the "next pc" being NOT the address of the next instruction in memory.

    Seeing something like this is very typical while interworking
    """
    qemu_assembly_run(ARM_IMPLICIT_BRANCH_NEXT_INSTRUCTION, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>        ldr    r1, [pc, #0x24]     R1, [_target+36] => 0x200bc (_target) ◂— 0x103eb02\n"
        "   0x200b8 <_start+4>      add    pc, r1, #1                  <_target>\n"
        "    ↓\n"
        "   0x200bc <_target>       add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200c0 <_target+4>     add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200c4 <_target+8>     add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200c8 <_target+12>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200cc <_target+16>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200d0 <_target+20>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200d4 <_target+24>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200d8 <_target+28>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "   0x200dc <_target+32>    add.w  r1, r2, r3          R1 => 0 (0 + 0)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_LDR_TO_PC = f"""
{ARM_PREAMBLE}

ldr    pc, =end
nop

end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_implicit_branch_ldr(qemu_assembly_run):
    """
    Like the previous test, but using the LDR instruction to load a value into the PC.

    These are very common as PLT trampolines:
        ldr    pc, [ip, #0xbf4]!           <printf>
    """
    qemu_assembly_run(ARM_LDR_TO_PC, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>    ldr    pc, [pc, #0xc]              <end>\n"
        "    ↓\n"
        "   0x200bc <end>       mov    r0, #0                  R0 => 0\n"
        "   0x200c0 <end+4>     mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x200c4 <end+8>     svc    #0 <SYS_exit_group>\n"
        "   0x200c8 <end+12>    strheq r0, [r2], -r12\n"
        "   0x200cc             andeq  r3, r0, r1, asr #32\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    gdb.execute("si")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        "   0x200b4 <_start>    ldr    pc, [pc, #0xc]              <end>\n"
        "    ↓\n"
        " ► 0x200bc <end>       mov    r0, #0                  R0 => 0\n"
        "   0x200c0 <end+4>     mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x200c4 <end+8>     svc    #0 <SYS_exit_group>\n"
        "   0x200c8 <end+12>    strheq r0, [r2], -r12\n"
        "   0x200cc             andeq  r3, r0, r1, asr #32\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


def test_arm_mode_banner(qemu_assembly_run):
    """
    Makes sure that we detect Arm mode correctly in the banner
    """
    qemu_assembly_run(ARM_INTERWORKING_BRANCH, "arm")

    out = gdb.execute("context disasm", to_string=True).split("\n")

    assert (
        out[1] == "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────"
    )

    gdb.execute("si 2")

    out = gdb.execute("context disasm", to_string=True).split("\n")

    assert (
        out[1] == "─────────────────[ DISASM / arm / thumb mode / set emulate on ]─────────────────"
    )


ARM_STACK_CRASH = f"""
{ARM_PREAMBLE}
mov r0, #4
mov r1, #3
add r2, r0, r1
sub r3, r2, #2
push {{r3}}
pop {{r4}}
mul r4, r2, r1
add r4, r4, #1
end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_stack_pointer_check(qemu_assembly_run):
    """
    This tests runs a small program that has an access to the stack in the middle.

    We are testing to ensure that Unicorn does not crash on this access to the stack pointer (the pop instruction).
    If the emulator registers are not instantiated in the correct order (CPSR is written AFTER stack pointer),
    the stack pointer will be reset to zero due to banked registers: https://github.com/unicorn-engine/unicorn/issues/1984

    If this test fails (annotations after the str/pop don't show), it likely means that the stack pointer has the incorrect value.

    See also: https://github.com/pwndbg/pwndbg/pull/2337
    """
    qemu_assembly_run(ARM_STACK_CRASH, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>       mov    r0, #4                  R0 => 4\n"
        "   0x200b8 <_start+4>     mov    r1, #3                  R1 => 3\n"
        "   0x200bc <_start+8>     add    r2, r0, r1              R2 => 7 (4 + 3)\n"
        "   0x200c0 <_start+12>    sub    r3, r2, #2              R3 => 5 (7 - 2)\n"
        f"   0x200c4 <_start+16>    str    r3, [sp, #-4]!          [{hex(pwndbg.aglib.regs.sp - 4)}] <= 5\n"
        "   0x200c8 <_start+20>    pop    {r4}\n"
        "   0x200cc <_start+24>    mul    r4, r2, r1              R4 => 21 (7 * 3)\n"
        "   0x200d0 <_start+28>    add    r4, r4, #1              R4 => 22 (0x15 + 0x1)\n"
        "   0x200d4 <end>          mov    r0, #0                  R0 => 0\n"
        "   0x200d8 <end+4>        mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x200dc <end+8>        svc    #0 <SYS_exit_group>\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_CMP = f"""
{ARM_PREAMBLE}
mov r0, #5
mov r1, #5
cmp r0, r1
beq end
nop
nop
nop
end:
{ARM_GRACEFUL_EXIT}
"""


def test_arm_cmp_instructions(qemu_assembly_run):
    qemu_assembly_run(ARM_CMP, "arm")
    dis = gdb.execute("context disasm", to_string=True)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>       mov    r0, #5     R0 => 5\n"
        "   0x200b8 <_start+4>     mov    r1, #5     R1 => 5\n"
        "   0x200bc <_start+8>     cmp    r0, r1     5 - 5     CPSR => 0x60000010 [ n Z C v q j t e a i f ]\n"
        "   0x200c0 <_start+12>  ✔ beq    end                         <end>\n"
        "    ↓\n"
        "   0x200d0 <end>          mov    r0, #0                  R0 => 0\n"
        "   0x200d4 <end+4>        mov    r7, #0xf8               R7 => 0xf8\n"
        "   0x200d8 <end+8>        svc    #0 <SYS_exit_group>\n"
        "   0x200dc                andeq  r3, r0, r1, asr #32\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_BRANCH_AND_LINK = f"""
{ARM_PREAMBLE}
nop
bl func
nop
nop

end:
{ARM_GRACEFUL_EXIT}

nop
nop
nop
nop

func:
mov r0, #0
bx lr
"""


def test_arm_call_instructions(qemu_assembly_run):
    """
    This test ensures that "call" instructions in Arm do not get unrolled.

    This means the `branch-and-link` instruction, `bl`
    """
    qemu_assembly_run(ARM_BRANCH_AND_LINK, "arm")

    dis = gdb.execute("context disasm", to_string=True)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>       nop    \n"
        "   0x200b8 <_start+4>     bl     func                        <func>\n"
        " \n"
        "   0x200bc <_start+8>     nop    \n"
        "   0x200c0 <_start+12>    nop    \n"
        "   0x200c4 <end>          mov    r0, #0        R0 => 0\n"
        "   0x200c8 <end+4>        mov    r7, #0xf8     R7 => 0xf8\n"
        "   0x200cc <end+8>        svc    #0\n"
        "   0x200d0 <end+12>       nop    \n"
        "   0x200d4 <end+16>       nop    \n"
        "   0x200d8 <end+20>       nop    \n"
        "   0x200dc <end+24>       nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_STORE = f"""
{ARM_PREAMBLE}
ldr r0, =value1
ldr r1, =0x87654321
ldr r2, =0x12345678

str r1, [r0]
strex r3, r2, [r0]
str r1, [r0], #1
add r0, r1
nop
nop
nop
nop
nop
{ARM_GRACEFUL_EXIT}

    .data
value1:
    .word 0x0
"""


def test_arm_exclusive_store(qemu_assembly_run):
    """
    This tests that we properly handle both stores, exclusive stores, and store with post-indexing
    """
    qemu_assembly_run(ARM_STORE, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200d4 <_start>       ldr    r0, [pc, #0x34]     R0, [_start+60] => 0x3011c (value1) ◂— 0\n"
        "   0x200d8 <_start+4>     ldr    r1, [pc, #0x34]     R1, [_start+64] => 0x87654321\n"
        "   0x200dc <_start+8>     ldr    r2, [pc, #0x34]     R2, [_start+68] => 0x12345678\n"
        "   0x200e0 <_start+12>    str    r1, [r0]            [value1] <= 0x87654321\n"
        "   0x200e4 <_start+16>    strex  r3, r2, [r0]        [value1] <= 0x12345678\n"
        "   0x200e8 <_start+20>    str    r1, [r0], #1        [value1] <= 0x87654321\n"
        "   0x200ec <_start+24>    add    r0, r0, r1          R0 => 0x8768443e (0x3011d + 0x87654321)\n"
        "   0x200f0 <_start+28>    nop    \n"
        "   0x200f4 <_start+32>    nop    \n"
        "   0x200f8 <_start+36>    nop    \n"
        "   0x200fc <_start+40>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_SHIFTS = f"""
{ARM_PREAMBLE}
MOV r0, #3
MOV r1, #0xF000
MOV r2, #0x1234
LSR r3, r1, #4
LSR r4, r1, r0
LSL r5, r4, #4
LSL r6, r4, r2
ASR r6, r4, #4
ASR r6, r4, r0
ROR r6, r4, #4
ROR r6, r4, r0
"""


def test_arm_logical_shifts(qemu_assembly_run):
    """
    Shifts have a different underlying Capstone representation if it's an constant or a register offset.
    This test ensures we handle both cases.
    """
    qemu_assembly_run(ARM_SHIFTS, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>       mov    r0, #3          R0 => 3\n"
        "   0x200b8 <_start+4>     mov    r1, #0xf000     R1 => 0xf000\n"
        "   0x200bc <_start+8>     movw   r2, #0x1234     R2 => 0x1234\n"
        "   0x200c0 <_start+12>    lsr    r3, r1, #4      R3 => 0xf00 (0xf000 >> 0x4)\n"
        "   0x200c4 <_start+16>    lsr    r4, r1, r0      R4 => 0x1e00 (0xf000 >> 0x3)\n"
        "   0x200c8 <_start+20>    lsl    r5, r4, #4      R5 => 0x1e000 (0x1e00 << 0x4)\n"
        "   0x200cc <_start+24>    lsl    r6, r4, r2      R6 => 0 (0x1e00 << 0x1234)\n"
        "   0x200d0 <_start+28>    asr    r6, r4, #4      R6 => 0x1e0 (0x1e00 >>s 0x4)\n"
        "   0x200d4 <_start+32>    asr    r6, r4, r0      R6 => 0x3c0 (0x1e00 >>s 0x3)\n"
        "   0x200d8 <_start+36>    ror    r6, r4, #4      R6 => 0x1e0 (0x1e00 >>r 0x4)\n"
        "   0x200dc <_start+40>    ror    r6, r4, r0      R6 => 0x3c0 (0x1e00 >>r 0x3)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


NEGATIVE_DISPONENTS = rf"""
{ARM_PREAMBLE}
LDR r1, =msg
ADD r1, 4
LDR r0, [r1, #-4]
nop
nop
nop
nop
nop
nop
nop
nop


.data
msg:
    .asciz "ABCDEFGHIJKLMNOPQRSTUVWXYZ!"
"""


def test_arm_negative_disponent(qemu_assembly_run):
    """
    Negative disponents are now represented by a positive offset and a flag that indicates it should be subtracted.
    This representation changed in CapstoneV6
    """
    qemu_assembly_run(NEGATIVE_DISPONENTS, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200d4 <_start>       ldr    r1, [pc, #0x24]     R1, [_start+44] => 0x30104 (msg) ◂— 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!'\n"
        "   0x200d8 <_start+4>     add    r1, r1, #4          R1 => 0x30108 (msg+4) (0x30104 + 0x4)\n"
        "   0x200dc <_start+8>     ldr    r0, [r1, #-4]       R0, [msg] => 0x44434241 ('ABCD')\n"
        "   0x200e0 <_start+12>    nop    \n"
        "   0x200e4 <_start+16>    nop    \n"
        "   0x200e8 <_start+20>    nop    \n"
        "   0x200ec <_start+24>    nop    \n"
        "   0x200f0 <_start+28>    nop    \n"
        "   0x200f4 <_start+32>    nop    \n"
        "   0x200f8 <_start+36>    nop    \n"
        "   0x200fc <_start+40>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


NEGATIVE_INDEX_REGISTER = rf"""
{ARM_PREAMBLE}
LDR R1, =msg
ADD r1, 4
ADD r2, r1, 4

MOV R3, #4
MOV R4, #2

LDR R5, [R1, -R3]
LDR R6, [R2, -R4, LSL #2]

nop
nop
nop
nop
nop
nop
nop

.data
msg:
    .asciz "ABCDEFGHIJKLMNOPQRSTUVWXYZ!"
"""


def test_arm_negative_index_register(qemu_assembly_run):
    """
    In the LDR instructions above, the index register is negated.

    This has a specific encoding that has changed in Capstone in the past, so we test to make sure we are handling it correctly.
    """

    qemu_assembly_run(NEGATIVE_INDEX_REGISTER, "arm")
    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200d4 <_start>       ldr    r1, [pc, #0x30]           R1, [_start+56] => 0x30110 (msg) ◂— 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!'\n"
        "   0x200d8 <_start+4>     add    r1, r1, #4                R1 => 0x30114 (msg+4) (0x30110 + 0x4)\n"
        "   0x200dc <_start+8>     add    r2, r1, #4                R2 => 0x30118 (msg+8) (0x30114 + 0x4)\n"
        "   0x200e0 <_start+12>    mov    r3, #4                    R3 => 4\n"
        "   0x200e4 <_start+16>    mov    r4, #2                    R4 => 2\n"
        "   0x200e8 <_start+20>    ldr    r5, [r1, -r3]             R5, [msg] => 0x44434241 ('ABCD')\n"
        "   0x200ec <_start+24>    ldr    r6, [r2, -r4, lsl #2]     R6, [msg] => 0x44434241 ('ABCD')\n"
        "   0x200f0 <_start+28>    nop    \n"
        "   0x200f4 <_start+32>    nop    \n"
        "   0x200f8 <_start+36>    nop    \n"
        "   0x200fc <_start+40>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


ARM_IT_BLOCK = f"""
{ARM_PREAMBLE}
add r0, pc, #1
bx r0

.THUMB
CMP     R0, #0
ITTTE   EQ
MOVEQ   R1, #1
MOVEQ   R2, #2
MOVEQ   R2, #3
MOVNE   R1, #4
nop
nop
nop
nop
nop
nop
"""


def test_arm_it_block(qemu_assembly_run):
    """
    The Unicorn engine cannot be paused in the IT block, so we need to handle these instructions specially.

    Additionally, if we are halfway through an IT block, and then copy the the process state into the emulator, it will finish the
    IT block upon single stepping, and sometimes step an additional step.
    """

    qemu_assembly_run(ARM_IT_BLOCK, "arm")

    gdb.execute("si")
    gdb.execute("si")

    dis_1 = gdb.execute("context disasm", to_string=True)
    dis_1 = pwndbg.color.strip(dis_1)

    expected_1 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────[ DISASM / arm / thumb mode / set emulate on ]─────────────────\n"
        " ► 0x200bc <_start+8>     cmp    r0, #0     0x200bd - 0x0     CPSR => 0x20000030 [ n z C v q j T e a i f ]\n"
        "   0x200be <_start+10>    ittte  eq\n"
        "   0x200c0 <_start+12>    movs   r1, #1     R1 => 1\n"
        "   0x200c2 <_start+14>    movs   r2, #2     R2 => 2\n"
        "   0x200c4 <_start+16>    movs   r2, #3     R2 => 3\n"
        "   0x200c6 <_start+18>    movs   r1, #4     R1 => 4\n"
        "   0x200c8 <_start+20>    nop    \n"
        "   0x200ca <_start+22>    nop    \n"
        "   0x200cc <_start+24>    nop    \n"
        "   0x200ce <_start+26>    nop    \n"
        "   0x200d0 <_start+28>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_1 == expected_1

    # Now, ensure that once we step into the block, the disassembly is still correct.
    gdb.execute("si")
    gdb.execute("si")
    gdb.execute("si")

    dis_2 = gdb.execute("context disasm", to_string=True)
    dis_2 = pwndbg.color.strip(dis_2)

    expected_2 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────[ DISASM / arm / thumb mode / set emulate on ]─────────────────\n"
        "   0x200bc <_start+8>     cmp    r0, #0     0x200bd - 0x0     CPSR => 0x20000030 [ n z C v q j T e a i f ]\n"
        "   0x200be <_start+10>    ittte  eq\n"
        "   0x200c0 <_start+12>    movs   r1, #1     R1 => 1\n"
        " ► 0x200c2 <_start+14>    movs   r2, #2     R2 => 2\n"
        "   0x200c4 <_start+16>    movs   r2, #3     R2 => 3\n"
        "   0x200c6 <_start+18>    movs   r1, #4     R1 => 4\n"
        "   0x200c8 <_start+20>    nop    \n"
        "   0x200ca <_start+22>    nop    \n"
        "   0x200cc <_start+24>    nop    \n"
        "   0x200ce <_start+26>    nop    \n"
        "   0x200d0 <_start+28>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_2 == expected_2


def test_arm_it_block_cached_thumb_mode(qemu_assembly_run):
    """
    This test ensures that we handle transitions to Thumb mode correctly once the emulator has been disabled.

    Emulation is disabled internally at the "ittte" instruction.
    """

    qemu_assembly_run(ARM_IT_BLOCK, "arm")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────[ DISASM / arm / arm mode / set emulate on ]──────────────────\n"
        " ► 0x200b4 <_start>       add    r0, pc, #1     R0 => 0x200bd (_start+9) (0x200bc + 0x1)\n"
        "   0x200b8 <_start+4>     bx     r0                          <_start+8>\n"
        "    ↓\n"
        "   0x200bc <_start+8>     cmp    r0, #0         0x200bd - 0x0     CPSR => 0x20000030 [ n z C v q j T e a i f ]\n"
        "   0x200be <_start+10>    ittte  eq\n"
        "   0x200c0 <_start+12>    movs   r1, #1         R1 => 1\n"
        "   0x200c2 <_start+14>    movs   r2, #2         R2 => 2\n"
        "   0x200c4 <_start+16>    movs   r2, #3         R2 => 3\n"
        "   0x200c6 <_start+18>    movs   r1, #4         R1 => 4\n"
        "   0x200c8 <_start+20>    nop    \n"
        "   0x200ca <_start+22>    nop    \n"
        "   0x200cc <_start+24>    nop    \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected
