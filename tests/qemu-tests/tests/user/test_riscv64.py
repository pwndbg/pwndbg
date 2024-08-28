from __future__ import annotations

import gdb
import user

import pwndbg.gdblib.symbol

RISCV64_GRACEFUL_EXIT = """
    li a2, 30
    li a7, 93
    li a0, 0
    ecall
"""

RISCV64_JALR = f"""
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
        " ► 0x10000000 <_start>       c.li   a0, 0xa          A0 => 0xa\n"
        "   0x10000002 <_start+2>     c.li   a1, 0x14         A1 => 0x14\n"
        "   0x10000004 <_start+4>     auipc  t0, 0            T0 => 0x10000004 (_start+4)\n"
        "   0x10000008 <_start+8>     addi   t0, t0, 0x20     T0 => 0x10000024 (function) (0x10000004 + 0x20)\n"
        "   0x1000000c <_start+12>    jalr   t0                          <function>\n"
        " \n"
        "   0x10000010 <_start+16>    add    a2, a0, a1\n"
        "   0x10000014 <_start+20>    auipc  t1, 0            T1 => 0x10000014 (_start+20)\n"
        "   0x10000018 <_start+24>    addi   t1, t1, 0x12\n"
        "   0x1000001c <_start+28>    jalr   t1\n"
        " \n"
        "   0x10000020 <_start+32>    c.nop  \n"
        "   0x10000022 <_start+34>    c.nop  \n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


RISCV64_COMPRESSED_LOAD_STORE = f"""
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
    RISC-V support in Capstone is fairly new, and as of Capstone 5, there are some inconsistenties, and the underlying
    metadata of the instructions can change between versions.

    Currently, compressed load and stores operations have a memory operand representation that is subject to change in Capstone v6.

    If this crashes, it is we likely need to update the parser for compressed memory operands.
    - Link: https://github.com/capstone-engine/capstone/issues/2351
    """
    qemu_assembly_run(RISCV64_COMPRESSED_LOAD_STORE, "riscv64")

    gdb.execute("b store")
    gdb.execute("c")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "───────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────\n"
        " ► 0x10000028 <store>       c.sd   a0, 0(a2)          [data] => 0x1234567890abcdef\n"
        "   0x1000002a <store+2>     c.ld   a1, 0(a2)          A1, [data] => 0x1234567890abcdef\n"
        "   0x1000002c <store+4>     c.li   a1, 0x10           A1 => 0x10\n"
        "   0x1000002e <store+6>     addi   a2, zero, 0x26     A2 => 38 (0x0 + 0x26)\n"
        "   0x10000032 <store+10>    add    a4, a1, a2         A4 => 54 (0x10 + 0x26)\n"
        "   0x10000036 <store+14>    sub    a5, a1, a3         A5 => 16 (0x10 - 0x0)\n"
        "   0x1000003a <store+18>    xor    a6, a1, a2         A6 => 54 (0x10 ^ 0x26)\n"
        "   0x1000003e <store+22>    and    a7, a1, a2         A7 => 0 (0x10 & 0x26)\n"
        "   0x10000042 <store+26>    sll    a3, a1, a2         A3 => 0x40000000000 (0x10 << 0x26)\n"
        "   0x10000046 <store+30>    mul    a2, a1, a2         A2 => 0x260 (0x10 * 0x26)\n"
        "   0x1000004a <store+34>    div    a5, a3, a2         A5 => 0x1af286bca (0x40000000000 / 0x260)\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


RISCV64_JUMPS = f"""
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
        " ► 0x10000000 <_start>      c.li   t0, 4     T0 => 4\n"
        "   0x10000002 <_start+2>    c.li   t1, 5     T1 => 5\n"
        "   0x10000004 <_start+4>    beq    t0, t1, 6                   <first>\n"
        " \n"
        "   0x10000008 <_start+8>    c.nop  \n"
        "   0x1000000a <first>     ✔ bne    t0, t2, 6                   <second>\n"
        "    ↓\n"
        "   0x10000010 <second>      blt    t0, t3, 6                   <third>\n"
        " \n"
        "   0x10000014 <second+4>    c.nop  \n"
        "   0x10000016 <third>     ✔ bge    t0, t4, 6                   <fourth>\n"
        "    ↓\n"
        "   0x1000001c <fourth>    ✔ blt    t5, t0, 6                   <end>\n"
        "    ↓\n"
        "   0x10000022 <end>         c.li   a2, 0x1e           A2 => 0x1e\n"
        "   0x10000024 <end+2>       addi   a7, zero, 0x5d     A7 => 93 (0x0 + 0x5d)\n"
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
        "   0x10000002 <_start+2>    c.li   t1, 5     T1 => 5\n"
        "   0x10000004 <_start+4>    beq    t0, t1, 6                   <first>\n"
        " \n"
        "   0x10000008 <_start+8>    c.nop  \n"
        "   0x1000000a <first>     ✔ bne    t0, t2, 6                   <second>\n"
        "    ↓\n"
        "   0x10000010 <second>      blt    t0, t3, 6                   <third>\n"
        " \n"
        " ► 0x10000014 <second+4>    c.nop  \n"
        "   0x10000016 <third>     ✔ bge    t0, t4, 6                   <fourth>\n"
        "    ↓\n"
        "   0x1000001c <fourth>    ✔ blt    t5, t0, 6                   <end>\n"
        "    ↓\n"
        "   0x10000022 <end>         c.li   a2, 0x1e           A2 => 0x1e\n"
        "   0x10000024 <end+2>       addi   a7, zero, 0x5d     A7 => 93 (0x0 + 0x5d)\n"
        "   0x10000028 <end+6>       c.li   a0, 0              A0 => 0\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


RISCV64_JUMP_CHAIN = f"""
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
        " ► 0x10000000 <_start>    c.j    2                           <a>\n"
        "    ↓\n"
        "   0x10000002 <a>         c.j    2                           <b>\n"
        "    ↓\n"
        "   0x10000004 <b>         c.j    2                           <c>\n"
        "    ↓\n"
        "   0x10000006 <c>         c.j    2                           <d>\n"
        "    ↓\n"
        "   0x10000008 <d>         c.j    2                           <e>\n"
        "    ↓\n"
        "   0x1000000a <e>         c.j    2                           <end>\n"
        "    ↓\n"
        "   0x1000000c <end>       c.li   a2, 0x1e           A2 => 0x1e\n"
        "   0x1000000e <end+2>     addi   a7, zero, 0x5d     A7 => 93 (0x0 + 0x5d)\n"
        "   0x10000012 <end+6>     c.li   a0, 0              A0 => 0\n"
        "   0x10000014 <end+8>     ecall   <SYS_exit>\n"
        "   0x10000018             c.addiw s6, -0x10\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


REFERENCE_BINARY = user.binaries.get("reference-binary.riscv64.out")


def test_riscv64_reference(qemu_start_binary):
    qemu_start_binary(REFERENCE_BINARY, "riscv64")
    gdb.execute("break 4")
    assert pwndbg.gdblib.symbol.address("main") is not None
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
