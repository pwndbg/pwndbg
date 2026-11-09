from __future__ import annotations

from collections.abc import Callable

import gdb

import pwndbg.color

from . import args_at_pc
from . import syscalls_at_pc

LOONGARCH64_PREAMBLE = """
.text
.globl _start
_start:

"""

LOONGARCH64_BRANCHES = f"""
{LOONGARCH64_PREAMBLE}

one:
    beqz $a0, two
    nop
    nop

two:
    la $t0, func
    jirl $ra,$t0,0
    b end
    nop
    nop

func:
    add.d $a0,$a0,$a1
    jr $ra
    nop

end:
    nop
    nop
    nop

"""


def test_loongarch64_simple_branches(qemu_assembly_run):
    qemu_assembly_run(LOONGARCH64_BRANCHES, "loongarch64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────[ DISASM / loongarch64 / set emulate on ]────────────────────\n"
        " ► 0x1010190 <_start>  ✔ beqz   $a0, two                    <two>\n"
        "    ↓\n"
        "   0x101019c <two>       pcalau12i $t0, 0x10\n"
        "   0x10101a0 <two+4>     ld.d   $t0, $t0, 0x1f4\n"
        "   0x10101a4 <two+8>     jirl   $ra, $t0, 0\n"
        " \n"
        "   0x10101a8 <two+12>    b      end                         <end>\n"
        "    ↓\n"
        "   0x10101c0 <end>       nop   \n"
        "   0x10101c4 <end+4>     nop   \n"
        "   0x10101c8 <end+8>     nop   \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


LOONGARCH64_CALL_AND_SYSCALL = f"""
{LOONGARCH64_PREAMBLE}
    li.d $a0, 1
    li.d $a1, 2
    li.d $a2, 3
    bl write
    li.d $a0, 0
    li.d $a7, 93
    syscall 0
    nop
    nop

write:
    jr $ra
"""


def test_loongarch64_function_arguments(qemu_assembly_run: Callable[..., None]) -> None:
    qemu_assembly_run(LOONGARCH64_CALL_AND_SYSCALL, "loongarch64")

    gdb.execute("stepuntilasm bl")

    assert args_at_pc() == [("fd", 1), ("buf", 2), ("n", 3)]


def test_loongarch64_syscall_annotation(qemu_assembly_run: Callable[..., None]) -> None:
    qemu_assembly_run(LOONGARCH64_CALL_AND_SYSCALL, "loongarch64")

    gdb.execute("stepuntilasm syscall")

    assert syscalls_at_pc() == [(93, "exit"), (93, "exit")]
    assert args_at_pc() == [("error_code", 0)]
