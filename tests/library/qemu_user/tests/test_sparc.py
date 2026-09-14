from __future__ import annotations

import gdb

import pwndbg.color

SPARC_PREAMBLE = """
.text
.globl _start
_start:
"""

SPARC_GRACEFUL_EXIT = """
mov 1, %g1
clr %o0
ta 0x10
nop
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


SPARC_DELAY_SLOT = f"""
{SPARC_PREAMBLE}

mov 7, %l0
cmp %l0, 7
be branch_target
nop
nop
nop
nop
nop
nop
nop
nop

branch_target:
mov     1, %l1
mov     1, %g1
mov     0, %o0

{SPARC_GRACEFUL_EXIT}
"""


def test_sparc64_delay_slot(qemu_assembly_run):
    """
    SPARC has delay slots, meaning that when a branch is encountered, there is a "delay" in the branch taking effect.
    The next instruction sequentially in memory is always executed, and then the result of the branch is applied.

    In the disasm output, we group the delay slot with the branch. After the delay slot instruction we put the blank line/line with a down arrow.

    This test makes sure that looking forwards, we determine branch slots directly, and after moving passed them, they stay intact.
    """
    qemu_assembly_run(SPARC_DELAY_SLOT, "sparc64")

    # Prime the cache for the first 2 instructions
    gdb.execute("context disasm", to_string=True)

    # Step to the branch
    gdb.execute("si")
    gdb.execute("si")

    dis_0 = gdb.execute("context disasm", to_string=True)
    dis_0 = pwndbg.color.strip(dis_0)

    expected_0 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / sparc / set emulate on ]───────────────────────\n"
        "   0x1100120 <_start>              mov    7, %l0\n"
        "   0x1100124 <_start+4>            cmp    %l0, 7\n"
        " ► 0x1100128 <_start+8>          ✔ be     branch_target               <branch_target>\n"
        "   0x110012c <_start+12>           nop   \n"
        "    ↓\n"
        "   0x110014c <branch_target>       mov    1, %l1\n"
        "   0x1100150 <branch_target+4>     mov    1, %g1\n"
        "   0x1100154 <branch_target+8>     mov    0, %o0\n"
        "   0x1100158 <branch_target+12>    mov    1, %g1\n"
        "   0x110015c <branch_target+16>    mov    %g0, %o0\n"
        "   0x1100160 <branch_target+20>    ta     %icc, 0x10\n"
        "   0x1100164 <branch_target+24>    nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_0 == expected_0

    gdb.execute("si")

    dis_1 = gdb.execute("context disasm", to_string=True)
    dis_1 = pwndbg.color.strip(dis_1)

    expected_1 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / sparc / set emulate on ]───────────────────────\n"
        "   0x1100120 <_start>              mov    7, %l0\n"
        "   0x1100124 <_start+4>            cmp    %l0, 7\n"
        "   0x1100128 <_start+8>          ✔ be     branch_target               <branch_target>\n"
        " ► 0x110012c <_start+12>           nop   \n"
        "    ↓\n"
        "   0x110014c <branch_target>       mov    1, %l1\n"
        "   0x1100150 <branch_target+4>     mov    1, %g1\n"
        "   0x1100154 <branch_target+8>     mov    0, %o0\n"
        "   0x1100158 <branch_target+12>    mov    1, %g1\n"
        "   0x110015c <branch_target+16>    mov    %g0, %o0\n"
        "   0x1100160 <branch_target+20>    ta     %icc, 0x10\n"
        "   0x1100164 <branch_target+24>    nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_1 == expected_1

    gdb.execute("si")

    dis_2 = gdb.execute("context disasm", to_string=True)
    dis_2 = pwndbg.color.strip(dis_2)

    expected_2 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / sparc / set emulate on ]───────────────────────\n"
        "   0x1100120 <_start>              mov    7, %l0\n"
        "   0x1100124 <_start+4>            cmp    %l0, 7\n"
        "   0x1100128 <_start+8>          ✔ be     branch_target               <branch_target>\n"
        "   0x110012c <_start+12>           nop   \n"
        "    ↓\n"
        " ► 0x110014c <branch_target>       mov    1, %l1\n"
        "   0x1100150 <branch_target+4>     mov    1, %g1\n"
        "   0x1100154 <branch_target+8>     mov    0, %o0\n"
        "   0x1100158 <branch_target+12>    mov    1, %g1\n"
        "   0x110015c <branch_target+16>    mov    %g0, %o0\n"
        "   0x1100160 <branch_target+20>    ta     %icc, 0x10\n"
        "   0x1100164 <branch_target+24>    nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_2 == expected_2

    gdb.execute("si")

    dis_3 = gdb.execute("context disasm", to_string=True)
    dis_3 = pwndbg.color.strip(dis_3)

    expected_3 = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / sparc / set emulate on ]───────────────────────\n"
        "   0x1100120 <_start>              mov    7, %l0\n"
        "   0x1100124 <_start+4>            cmp    %l0, 7\n"
        "   0x1100128 <_start+8>          ✔ be     branch_target               <branch_target>\n"
        "   0x110012c <_start+12>           nop   \n"
        "    ↓\n"
        "   0x110014c <branch_target>       mov    1, %l1\n"
        " ► 0x1100150 <branch_target+4>     mov    1, %g1\n"
        "   0x1100154 <branch_target+8>     mov    0, %o0\n"
        "   0x1100158 <branch_target+12>    mov    1, %g1\n"
        "   0x110015c <branch_target+16>    mov    %g0, %o0\n"
        "   0x1100160 <branch_target+20>    ta     %icc, 0x10\n"
        "   0x1100164 <branch_target+24>    nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis_3 == expected_3
