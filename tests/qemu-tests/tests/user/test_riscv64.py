from __future__ import annotations

import gdb
import user

import pwndbg.aglib.symbol
import pwndbg.color
import pwndbg.dbg

RISCV64_PREAMBLE = """
.text
.globl _start
_start:
"""

RISCV64_GRACEFUL_EXIT = """
    li a2, 30
    li a7, 93
    li a0, 0
    ecall
"""

RISCV64_JALR = f"""
{RISCV64_PREAMBLE}
li a0, 10
li a1, 20

la t0, function
jalr ra, t0, 0

add a2, a0, a1

la t1, end
jalr ra, t1, 0

nop
nop

function:
    jr ra

end:
{RISCV64_GRACEFUL_EXIT}
"""


def test_riscv64_jalr(qemu_assembly_run):
    """
    Test that we resolve jalr branch correctly (don't crash) and that there are corresponding splits in the disassembly.
    """
    qemu_assembly_run(RISCV64_JALR, "riscv64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────\n"
        " ► 0x1001158 <_start>       c.li   a0, 0xa          A0 => 0xa\n"
        "   0x100115a <_start+2>     c.li   a1, 0x14         A1 => 0x14\n"
        "   0x100115c <_start+4>     auipc  t0, 0            T0 => 0x100115c (_start+4)\n"
        "   0x1001160 <_start+8>     addi   t0, t0, 0x1c     T0 => 0x1001178 (function) (0x100115c + 0x1c)\n"
        "   0x1001164 <_start+12>    c.jalr t0                          <function>\n"
        " \n"
        "   0x1001166 <_start+14>    add    a2, a0, a1\n"
        "   0x100116a <_start+18>    auipc  t1, 0            T1 => 0x100116a (_start+18)\n"
        "   0x100116e <_start+22>    addi   t1, t1, 0x10\n"
        "   0x1001172 <_start+26>    c.jalr t1\n"
        " \n"
        "   0x1001174 <_start+28>    c.nop  \n"
        "   0x1001176 <_start+30>    c.nop  \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


RISCV64_COMPRESSED_LOAD_STORE = f"""
{RISCV64_PREAMBLE}
li a0, 0x1234567890ABCDEF
la a2, data

nop
nop
nop

store:
c.sd a0, 0(a2)
c.ld a1, 0(a2)

li a1, 0x10
li a2, 0x26

add a4, a1, a2
sub a5, a1, a3
xor a6, a1, a2
and a7, a1, a2
sll a3, a1, a2
mul a2, a1, a2
div a5, a3, a2

end:
{RISCV64_GRACEFUL_EXIT}

    .data
data:
    .dword 0
    .dword 0
"""


def test_riscv64_compressed_loads(qemu_assembly_run):
    """
    RISC-V support in Capstone is fairly new, and the underlying metadata of the instructions can change between versions.

    This test ensures that we properly handle compressed load and stores instruction, as the data representation changed between v5 and v6.
    """
    qemu_assembly_run(RISCV64_COMPRESSED_LOAD_STORE, "riscv64")

    gdb.execute("b store")
    gdb.execute("c")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────\n"
        " ► 0x10011b8 <store>       c.sd   a0, 0(a2)          [data] <= 0x1234567890abcdef\n"
        "   0x10011ba <store+2>     c.ld   a1, 0(a2)          A1, [data] => 0x1234567890abcdef\n"
        "   0x10011bc <store+4>     c.li   a1, 0x10           A1 => 0x10\n"
        "   0x10011be <store+6>     addi   a2, zero, 0x26     A2 => 38 (0x0 + 0x26)\n"
        "   0x10011c2 <store+10>    add    a4, a1, a2         A4 => 54 (0x10 + 0x26)\n"
        "   0x10011c6 <store+14>    sub    a5, a1, a3         A5 => 16 (0x10 - 0x0)\n"
        "   0x10011ca <store+18>    xor    a6, a1, a2         A6 => 54 (0x10 ^ 0x26)\n"
        "   0x10011ce <store+22>    and    a7, a1, a2         A7 => 0 (0x10 & 0x26)\n"
        "   0x10011d2 <store+26>    sll    a3, a1, a2         A3 => 0x40000000000 (0x10 << 0x26)\n"
        "   0x10011d6 <store+30>    mul    a2, a1, a2         A2 => 0x260 (0x10 * 0x26)\n"
        "   0x10011da <store+34>    div    a5, a3, a2         A5 => 0x1af286bca (0x40000000000 / 0x260)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


RISCV64_JUMPS = f"""
{RISCV64_PREAMBLE}
li t0, 4
li t1, 5
beq t0, t1, first
nop

first:
    bne t0, t2, second
    nop

second:
    blt t0, t3, third
    nop

third:
    bge t0, t4, fourth
    nop

fourth:
    blt t5, t0, end
    nop

end:
{RISCV64_GRACEFUL_EXIT}
"""


def test_riscv64_jumps(qemu_assembly_run):
    """
    Make sure jumps are resolved and caching works correctly
    """
    qemu_assembly_run(RISCV64_JUMPS, "riscv64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────\n"
        " ► 0x1001158 <_start>      c.li   t0, 4     T0 => 4\n"
        "   0x100115a <_start+2>    c.li   t1, 5     T1 => 5\n"
        "   0x100115c <_start+4>    beq    t0, t1, 6                   <first>\n"
        " \n"
        "   0x1001160 <_start+8>    c.nop  \n"
        "   0x1001162 <first>     ✔ bne    t0, t2, 6                   <second>\n"
        "    ↓\n"
        "   0x1001168 <second>      blt    t0, t3, 6                   <third>\n"
        " \n"
        "   0x100116c <second+4>    c.nop  \n"
        "   0x100116e <third>     ✔ bge    t0, t4, 6                   <fourth>\n"
        "    ↓\n"
        "   0x1001174 <fourth>    ✔ blt    t5, t0, 6                   <end>\n"
        "    ↓\n"
        "   0x100117a <end>         c.li   a2, 0x1e           A2 => 0x1e\n"
        "   0x100117c <end+2>       addi   a7, zero, 0x5d     A7 => 93 (0x0 + 0x5d)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected

    # Make sure the instructions are cached correctly across jumps
    gdb.execute("break *second+4")
    gdb.execute("c")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────\n"
        "   0x100115a <_start+2>    c.li   t1, 5     T1 => 5\n"
        "   0x100115c <_start+4>    beq    t0, t1, 6                   <first>\n"
        " \n"
        "   0x1001160 <_start+8>    c.nop  \n"
        "   0x1001162 <first>     ✔ bne    t0, t2, 6                   <second>\n"
        "    ↓\n"
        "   0x1001168 <second>      blt    t0, t3, 6                   <third>\n"
        " \n"
        " ► 0x100116c <second+4>    c.nop  \n"
        "   0x100116e <third>     ✔ bge    t0, t4, 6                   <fourth>\n"
        "    ↓\n"
        "   0x1001174 <fourth>    ✔ blt    t5, t0, 6                   <end>\n"
        "    ↓\n"
        "   0x100117a <end>         c.li   a2, 0x1e           A2 => 0x1e\n"
        "   0x100117c <end+2>       addi   a7, zero, 0x5d     A7 => 93 (0x0 + 0x5d)\n"
        "   0x1001180 <end+6>       c.li   a0, 0              A0 => 0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


RISCV64_JUMP_CHAIN = f"""
{RISCV64_PREAMBLE}
j a

a:
    j b

b:
    j c

c:
    j d

d:
    j e

e:
    j end

end:
{RISCV64_GRACEFUL_EXIT}
"""


def test_riscv64_jump_chain(qemu_assembly_run):
    """
    This test checks a sneaky edge case - when a jump target goes to the next address linearly in memory.

    Typically, we can determine jumps by seeing if the `next` address is NOT the address of the next instruction in memory, so this requires
    manual handling to make sure that the target is correctly displayed.
    """
    qemu_assembly_run(RISCV64_JUMP_CHAIN, "riscv64")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────\n"
        " ► 0x1001158 <_start>    c.j    2                           <a>\n"
        "    ↓\n"
        "   0x100115a <a>         c.j    2                           <b>\n"
        "    ↓\n"
        "   0x100115c <b>         c.j    2                           <c>\n"
        "    ↓\n"
        "   0x100115e <c>         c.j    2                           <d>\n"
        "    ↓\n"
        "   0x1001160 <d>         c.j    2                           <e>\n"
        "    ↓\n"
        "   0x1001162 <e>         c.j    2                           <end>\n"
        "    ↓\n"
        "   0x1001164 <end>       c.li   a2, 0x1e           A2 => 0x1e\n"
        "   0x1001166 <end+2>     addi   a7, zero, 0x5d     A7 => 93 (0x0 + 0x5d)\n"
        "   0x100116a <end+6>     c.li   a0, 0              A0 => 0\n"
        "   0x100116c <end+8>     ecall   <SYS_exit>\n"
        "   0x1001170             c.addiw s6, -0x10\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


REFERENCE_BINARY = user.binaries.get("reference-binary.riscv64.out")


def test_riscv64_reference(qemu_start_binary):
    qemu_start_binary(REFERENCE_BINARY, "riscv64")
    gdb.execute("break 4")
    assert pwndbg.aglib.symbol.lookup_symbol("main") is not None
    gdb.execute("continue")

    gdb.execute("stepuntilasm jalr")

    # verify call argument are enriched
    assembly = gdb.execute("nearpc", to_string=True)
    assert "'Not enough args'" in assembly

    gdb.execute("stepuntilasm c.jalr")

    # verify jump target is correct
    assembly = gdb.execute("nearpc 0", to_string=True)
    target = assembly.splitlines()[0].split()[-1]
    gdb.execute("stepi")
    assembly = gdb.execute("nearpc 0", to_string=True)
    assert assembly.split()[2] == target, (assembly.split()[2], target)
