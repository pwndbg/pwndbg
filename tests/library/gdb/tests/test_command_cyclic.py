from __future__ import annotations

import gdb
from pwnlib.util.cyclic import cyclic

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_cyclic_value(start_binary):
    """
    Tests lookup on a constant value
    """
    start_binary(REFERENCE_BINARY)

    ptr_size = pwndbg.aglib.arch.ptrsize
    test_offset = 37
    pattern = cyclic(length=80, n=ptr_size)
    val = int.from_bytes(pattern[test_offset : test_offset + ptr_size], pwndbg.aglib.arch.endian)
    out = gdb.execute(f"cyclic -l {hex(val)}", to_string=True)

    assert out == (
        "Finding cyclic pattern of 8 bytes: b'aaafaaaa' (hex: 0x6161616661616161)\n"
        "Found at offset 37\n"
    )


def test_command_cyclic_register(start_binary):
    """
    Tests lookup on a register
    """
    start_binary(REFERENCE_BINARY)

    ptr_size = pwndbg.aglib.arch.ptrsize
    test_offset = 45
    pattern = cyclic(length=80, n=ptr_size)
    pwndbg.aglib.regs.rdi = int.from_bytes(
        pattern[test_offset : test_offset + ptr_size], pwndbg.aglib.arch.endian
    )
    out = gdb.execute("cyclic -l $rdi", to_string=True)

    assert out == (
        "Finding cyclic pattern of 8 bytes: b'aaagaaaa' (hex: 0x6161616761616161)\n"
        "Found at offset 45\n"
    )


def test_command_cyclic_address(start_binary):
    """
    Tests lookup on a memory address
    """
    start_binary(REFERENCE_BINARY)

    addr = pwndbg.aglib.regs.rsp
    ptr_size = pwndbg.aglib.arch.ptrsize
    test_offset = 48
    pattern = cyclic(length=80, n=ptr_size)
    pwndbg.aglib.memory.write(addr, pattern)
    out = gdb.execute(f"cyclic -l '{{unsigned long}}{hex(addr + test_offset)}'", to_string=True)

    assert out == (
        "Finding cyclic pattern of 8 bytes: b'gaaaaaaa' (hex: 0x6761616161616161)\n"
        "Found at offset 48\n"
    )


def test_command_cyclic_wrong_alphabet():
    out = gdb.execute("cyclic -l 1234", to_string=True)
    assert out == (
        "Finding cyclic pattern of 4 bytes: b'\\xd2\\x04\\x00\\x00' (hex: 0xd2040000)\n"
        "Pattern contains characters not present in the alphabet\n"
    )


def test_command_cyclic_wrong_length():
    out = gdb.execute("cyclic -l qwerty", to_string=True)
    assert out == (
        "Lookup pattern must be 4 bytes (use `-n <length>` to lookup pattern of different length)\n"
    )
