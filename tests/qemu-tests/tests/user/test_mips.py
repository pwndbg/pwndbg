from __future__ import annotations

import gdb

import pwndbg

MIPS_GRACEFUL_EXIT = """
li $v0, 0xfa1
li $a0, 0
syscall
"""

MIPS_DELAY_SLOT = f"""
beq $t1, $t0, _target
nop

_target:
    addu  $gp, $gp, $ra
    nop

end:
{MIPS_GRACEFUL_EXIT}
"""


def test_mips32_delay_slot(qemu_assembly_run):
    """
    MIPS has delay slots, meaning that when a branch is encountered, they is a "delay" in the branch taking effect.
    The next instruction sequentially in memory is always executed, and then the result of the branch is applied.

    In the disasm output, we group the delay slot with the branch. After the delay slot instruction we put the blank line/line with a down arrow.

    This test makes sure that looking forwards, we determine branch slots directly, and after moving passed them, they stay intact.
    """
    qemu_assembly_run(MIPS_DELAY_SLOT, "mips")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / mips / set emulate on ]───────────────────────\n"
        " ► 0x10000000 <_start>     ✔ beq    $t1, $t0, _target           <_target>\n"
        "   0x10000004 <_start+4>     nop    \n"
        "    ↓\n"
        "   0x10000008 <_target>      addu   $gp, $gp, $ra         GP => 0 + 0\n"
        "   0x1000000c <_target+4>    nop    \n"
        "   0x10000010 <end>          addiu  $v0, $zero, 0xfa1\n"
        "   0x10000014 <end+4>        addiu  $a0, $zero, 0\n"
        "   0x10000018 <end+8>        syscall \n"
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
        "   0x10000000 <_start>     ✔ beq    $t1, $t0, _target           <_target>\n"
        "   0x10000004 <_start+4>     nop    \n"
        "    ↓\n"
        " ► 0x10000008 <_target>      addu   $gp, $gp, $ra         GP => 0 (0 + 0)\n"
        "   0x1000000c <_target+4>    nop    \n"
        "   0x10000010 <end>          addiu  $v0, $zero, 0xfa1     V0 => 0xfa1 (0x0 + 0xfa1)\n"
        "   0x10000014 <end+4>        addiu  $a0, $zero, 0         A0 => 0 (0 + 0)\n"
        "   0x10000018 <end+8>        syscall \n"
        "\n"
        "\n"
        "\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert after_step == expected


def test_mips32_call_instruction(qemu_assembly_run):
    """
    Ensure that MIPS "branch-and-link" instructions like "BAL" do not get unrolled.
    """
    pass
