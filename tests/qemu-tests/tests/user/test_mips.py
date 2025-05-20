from __future__ import annotations

import gdb
import pytest

import pwndbg.color

# Zig requires the start symbol to be __start instead of _start for MIPS
MIPS_PREAMBLE = """
.text
.globl __start
__start:
"""

MIPS_GRACEFUL_EXIT = """
li $v0, 0xfa1
li $a0, 0
syscall
.byte 0xFF, 0xFF
.byte 0xFF, 0xFF
.byte 0xFF, 0xFF
.byte 0xFF, 0xFF
.byte 0xFF, 0xFF
"""
# The .bytes form invalid instructions that don't get disassembled,
# leaving blanks lines in the disasm view


MIPS_DELAY_SLOT = f"""
{MIPS_PREAMBLE}

beq $t1, $t0, _target
nop

_target:
    addu  $gp, $gp, $ra
    nop

end:
{MIPS_GRACEFUL_EXIT}
"""


@pytest.mark.parametrize("arch", ["mips32", "mipsel32"])
def test_mips32_delay_slot(qemu_assembly_run, arch):
    """
    MIPS has delay slots, meaning that when a branch is encountered, they is a "delay" in the branch taking effect.
    The next instruction sequentially in memory is always executed, and then the result of the branch is applied.

    In the disasm output, we group the delay slot with the branch. After the delay slot instruction we put the blank line/line with a down arrow.

    This test makes sure that looking forwards, we determine branch slots directly, and after moving passed them, they stay intact.
    """
    qemu_assembly_run(MIPS_DELAY_SLOT, arch)

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x20150 <__start>    ✔ beq    $t1, $t0, _target           <_target>\n"
        "   0x20154 <__start+4>    nop    \n"
        "    ↓\n"
        "   0x2015c <_target>      addu   $gp, $gp, $ra         GP => 0 (0 + 0)\n"
        "   0x20160 <_target+4>    nop    \n"
        "   0x20164 <end>          addiu  $v0, $zero, 0xfa1     V0 => 0xfa1 (0x0 + 0xfa1)\n"
        "   0x20168 <end+4>        addiu  $a0, $zero, 0         A0 => 0 (0 + 0)\n"
        "   0x2016c <end+8>        syscall \n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    # Now, ensure the delay slot is kept intact when we step past it
    gdb.execute("si")

    after_step = gdb.execute("context disasm", to_string=True)
    after_step = pwndbg.color.strip(after_step)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        "   0x20150 <__start>    ✔ beq    $t1, $t0, _target           <_target>\n"
        "   0x20154 <__start+4>    nop    \n"
        "    ↓\n"
        " ► 0x2015c <_target>      addu   $gp, $gp, $ra         GP => 0 (0 + 0)\n"
        "   0x20160 <_target+4>    nop    \n"
        "   0x20164 <end>          addiu  $v0, $zero, 0xfa1     V0 => 0xfa1 (0x0 + 0xfa1)\n"
        "   0x20168 <end+4>        addiu  $a0, $zero, 0         A0 => 0 (0 + 0)\n"
        "   0x2016c <end+8>        syscall \n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert after_step == expected


MIPS_BNEZ = f"""
{MIPS_PREAMBLE}

li $t0, 10
bnez $t0, end
nop
nop
nop

end:
{MIPS_GRACEFUL_EXIT}
"""


@pytest.mark.parametrize("arch", ["mips32", "mipsel32"])
def test_mips32_bnez_instruction(qemu_assembly_run, arch):
    """
    Test that conditional branches work, with and without emulation.
    """
    qemu_assembly_run(MIPS_BNEZ, arch)

    dis_1 = gdb.execute("context disasm", to_string=True)
    dis_1 = pwndbg.color.strip(dis_1)

    expected_1 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x20150 <__start>      addiu  $t0, $zero, 0xa     T0 => 10 (0x0 + 0xa)\n"
        "   0x20154 <__start+4>  ✔ bnez   $t0, end                    <end>\n"
        "   0x20158 <__start+8>    nop    \n"
        "    ↓\n"
        "   0x20168 <end>          addiu  $v0, $zero, 0xfa1     V0 => 0xfa1 (0x0 + 0xfa1)\n"
        "   0x2016c <end+4>        addiu  $a0, $zero, 0         A0 => 0 (0 + 0)\n"
        "   0x20170 <end+8>        syscall \n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_1 == expected_1

    gdb.execute("set emulate off")
    no_emulate_dis_2 = gdb.execute("context disasm", to_string=True)
    no_emulate_dis_2 = pwndbg.color.strip(no_emulate_dis_2)

    # Without emulation, we cannot determine whether or not we take the branch yet
    # So the disasm output should just contain the instructions linearly in memory
    expected_2 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / mips / set emulate off ]───────────────────────\n"
        " ► 0x20150 <__start>       addiu  $t0, $zero, 0xa     T0 => 0x0 + 0xa\n"
        "   0x20154 <__start+4>     bnez   $t0, end                    <end>\n"
        "   0x20158 <__start+8>     nop    \n"
        " \n"
        "   0x2015c <__start+12>    nop    \n"
        "   0x20160 <__start+16>    nop    \n"
        "   0x20164 <__start+20>    nop    \n"
        "   0x20168 <end>           addiu  $v0, $zero, 0xfa1\n"
        "   0x2016c <end+4>         addiu  $a0, $zero, 0\n"
        "   0x20170 <end+8>         syscall \n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert no_emulate_dis_2 == expected_2

    # Once we are on the instruction, the branch target should be manually determined
    gdb.execute("si")

    no_emulate_dis_3 = gdb.execute("context disasm", to_string=True)
    no_emulate_dis_3 = pwndbg.color.strip(no_emulate_dis_3)

    expected_3 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / mips / set emulate off ]───────────────────────\n"
        "   0x20150 <__start>      addiu  $t0, $zero, 0xa     T0 => 0x0 + 0xa\n"
        " ► 0x20154 <__start+4>  ✔ bnez   $t0, end                    <end>\n"
        "   0x20158 <__start+8>    nop    \n"
        "    ↓\n"
        "   0x20168 <end>          addiu  $v0, $zero, 0xfa1\n"
        "   0x2016c <end+4>        addiu  $a0, $zero, 0\n"
        "   0x20170 <end+8>        syscall \n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert no_emulate_dis_3 == expected_3


MIPS_CALL = f"""
{MIPS_PREAMBLE}

jal my_function
nop
j end
nop

my_function:
    jr $ra

end:
{MIPS_GRACEFUL_EXIT}
"""


@pytest.mark.parametrize("arch", ["mips32", "mipsel32"])
def test_mips32_call_instruction(qemu_assembly_run, arch):
    """
    Ensure that MIPS "branch-and-link" instructions like "JAL" do not get unrolled, and have splits in disassembly correctly.

    There's a bug in Capstone which doesn't consider JAL a jump-like/call instruction, so we have to manually add the jump group.
    See: https://github.com/capstone-engine/capstone/issues/2448
    """
    qemu_assembly_run(MIPS_CALL, arch)

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x20150 <__start>       jal    my_function                 <my_function>\n"
        "        $a0:       0\n"
        "        $a1:       0\n"
        "        $a2:       0\n"
        "        $a3:       0\n"
        "   0x20154 <__start+4>     nop    \n"
        " \n"
        "   0x20158 <__start+8>     nop    \n"
        "   0x2015c <__start+12>    j      end                         <end>\n"
        "   0x20160 <__start+16>    nop    \n"
        "    ↓\n"
        "   0x20170 <end>           addiu  $v0, $zero, 0xfa1\n"
        "   0x20174 <end+4>         addiu  $a0, $zero, 0\n"
        "   0x20178 <end+8>         syscall \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    # Step to "end"
    gdb.execute("ni", to_string=True)
    gdb.execute("si", to_string=True)
    gdb.execute("si", to_string=True)

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        "   0x20150 <__start>       jal    my_function                 <my_function>\n"
        "   0x20154 <__start+4>     nop    \n"
        " \n"
        "   0x20158 <__start+8>     nop    \n"
        "   0x2015c <__start+12>    j      end                         <end>\n"
        "   0x20160 <__start+16>    nop    \n"
        "    ↓\n"
        " ► 0x20170 <end>           addiu  $v0, $zero, 0xfa1     V0 => 0xfa1 (0x0 + 0xfa1)\n"
        "   0x20174 <end+4>         addiu  $a0, $zero, 0         A0 => 0 (0 + 0)\n"
        "   0x20178 <end+8>         syscall \n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


MIPS_STORE_INSTRUCTIONS = f"""
{MIPS_PREAMBLE}

li $t0, 0x12345678

la $s0, value1
sw $t0, 0($s0)

la $s1, value2
sh $t0, 0($s1)

la $s2, value3
sb $t0, 0($s2)

    .data
value1: .word 0
value2: .short 0
value3: .byte 0
"""


@pytest.mark.parametrize("arch", ["mips32", "mipsel32"])
def test_mips32_store_instruction(qemu_assembly_run, arch):
    """
    Ensure all store instructions are annotated correctly.

    The assembly is very specific - note the .data section and the size of the variables.
    """
    qemu_assembly_run(MIPS_STORE_INSTRUCTIONS, arch)

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x20150 <__start>       lui    $t0, 0x1234          T0 => 0x12340000\n"
        "   0x20154 <__start+4>     ori    $t0, $t0, 0x5678     T0 => 0x12345678 (0x12340000 | 0x5678)\n"
        "   0x20158 <__start+8>     lui    $s0, 3               S0 => 0x30000\n"
        "   0x2015c <__start+12>    addiu  $s0, $s0, 0x180      S0 => 0x30180 (value1) (0x30000 + 0x180)\n"
        "   0x20160 <__start+16>    sw     $t0, 0($s0)          [value1] <= 0x12345678\n"
        "   0x20164 <__start+20>    lui    $s1, 3               S1 => 0x30000\n"
        "   0x20168 <__start+24>    addiu  $s1, $s1, 0x184      S1 => 0x30184 (value2) (0x30000 + 0x184)\n"
        "   0x2016c <__start+28>    sh     $t0, 0($s1)          [value2] <= 0x5678\n"
        "   0x20170 <__start+32>    lui    $s2, 3               S2 => 0x30000\n"
        "   0x20174 <__start+36>    addiu  $s2, $s2, 0x186      S2 => 0x30186 (value3) (0x30000 + 0x186)\n"
        "   0x20178 <__start+40>    sb     $t0, 0($s2)          [value3] <= 0x78\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


MIPS_LOAD_INSTRUCTIONS = f"""
{MIPS_PREAMBLE}

li $t0, 0xFFFFFFFF

la $s0, value1
sw $t0, 0($s0)

la $s1, value2
sh $t0, 0($s1)

la $s2, value3
sb $t0, 0($s2)

nop
nop
nop
nop

loads:
    lw $t1, 0($s0)
    lhu $t2, 0($s1)
    lbu $t3, 0($s2)

    lw $t4, 0($s0)
    lh $t5, 0($s1)
    lb $t6, 0($s2)

.byte 0xFF, 0xFF
.byte 0xFF, 0xFF
.byte 0xFF, 0xFF

        .data
value1: .word 0
value2: .short 0
value3: .byte 0
"""


@pytest.mark.parametrize("arch", ["mips32", "mipsel32"])
def test_mips32_load_instructions(qemu_assembly_run, arch):
    """
    This test ensures our logic for load instructions - including sign-extension - is working correctly.

    The size of the data reads is very important - the variables in the assembly have specific sizes to check that our reads don't overlap into other variables.

    The signed reads should signed extend from the read size to 32-bits.
    """
    qemu_assembly_run(MIPS_LOAD_INSTRUCTIONS, arch)

    gdb.execute("b loads")
    gdb.execute("c")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x20188 <loads>       lw     $t1, 0($s0)     T1, [value1] => 0xffffffff\n"
        "   0x2018c <loads+4>     lhu    $t2, 0($s1)     T2, [value2] => 0xffff\n"
        "   0x20190 <loads+8>     lbu    $t3, 0($s2)     T3, [value3] => 0xff\n"
        "   0x20194 <loads+12>    lw     $t4, 0($s0)     T4, [value1] => 0xffffffff\n"
        "   0x20198 <loads+16>    lh     $t5, 0($s1)     T5, [value2] => 0xffffffff\n"
        "   0x2019c <loads+20>    lb     $t6, 0($s2)     T6, [value3] => 0xffffffff\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


MIPS_BINARY_OPERATIONS = f"""
{MIPS_PREAMBLE}

li $t0, 10
li $t1, 20

add $t2, $t0, $t1
sub $t3, $t1, $t0
and $t4, $t0, $t1
or $t5, $t0, $t1
xor $t6, $t0, $t1
sll $t7, $t0, 2
srl $t8, $t1, 2
sllv $t8, $t1, $t8
srlv $t3, $t8, $t5
"""


@pytest.mark.parametrize("arch", ["mips32", "mipsel32"])
def test_mips32_binary_operations(qemu_assembly_run, arch):
    qemu_assembly_run(MIPS_BINARY_OPERATIONS, arch)

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x20150 <__start>       addiu  $t0, $zero, 0xa      T0 => 10 (0x0 + 0xa)\n"
        "   0x20154 <__start+4>     addiu  $t1, $zero, 0x14     T1 => 20 (0x0 + 0x14)\n"
        "   0x20158 <__start+8>     add    $t2, $t0, $t1        T2 => 30 (0xa + 0x14)\n"
        "   0x2015c <__start+12>    sub    $t3, $t1, $t0        T3 => 10 (0x14 - 0xa)\n"
        "   0x20160 <__start+16>    and    $t4, $t0, $t1        T4 => 0 (0xa & 0x14)\n"
        "   0x20164 <__start+20>    or     $t5, $t0, $t1        T5 => 30 (0xa | 0x14)\n"
        "   0x20168 <__start+24>    xor    $t6, $t0, $t1        T6 => 30 (0xa ^ 0x14)\n"
        "   0x2016c <__start+28>    sll    $t7, $t0, 2          T7 => 40 (0xa << 0x2)\n"
        "   0x20170 <__start+32>    srl    $t8, $t1, 2          T8 => 5 (0x14 >> 0x2)\n"
        "   0x20174 <__start+36>    sllv   $t8, $t1, $t8        T8 => 0x280 (0x14 << 0x5)\n"
        "   0x20178 <__start+40>    srlv   $t3, $t8, $t5        T3 => 0 (0x280 >> 0x1e)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


MIPS_JUMPS = f"""
{MIPS_PREAMBLE}

nop
beq $t1, $t0, first
nop
nop

first:
    li $t0, 10
    bnez $t0, second
    nop
    nop

second:
    b end
    nop
    nop

end:
{MIPS_GRACEFUL_EXIT}
"""


@pytest.mark.parametrize("arch", ["mips32", "mipsel32"])
def test_mips32_multiple_branches_followed(qemu_assembly_run, arch):
    """
    Ensure that emulation is setup correctly so as to follow multiple branches - bugs in how we handle delay slots and disable the emulator might break this.
    """
    qemu_assembly_run(MIPS_JUMPS, arch)

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x20150 <__start>      nop    \n"
        "   0x20154 <__start+4>  ✔ beq    $t1, $t0, first             <first>\n"
        "   0x20158 <__start+8>    nop    \n"
        "    ↓\n"
        "   0x20164 <first>        addiu  $t0, $zero, 0xa     T0 => 10 (0x0 + 0xa)\n"
        "   0x20168 <first+4>    ✔ bnez   $t0, second                 <second>\n"
        "   0x2016c <first+8>      nop    \n"
        "    ↓\n"
        "   0x20178 <second>       b      end                         <end>\n"
        "   0x2017c <second+4>     nop    \n"
        "    ↓\n"
        "   0x20188 <end>          addiu  $v0, $zero, 0xfa1     V0 => 0xfa1 (0x0 + 0xfa1)\n"
        "   0x2018c <end+4>        addiu  $a0, $zero, 0         A0 => 0 (0 + 0)\n"
        "   0x20190 <end+8>        syscall \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected
