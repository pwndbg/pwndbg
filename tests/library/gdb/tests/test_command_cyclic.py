from __future__ import annotations

import gdb
from pwnlib.util.cyclic import cyclic

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.out")


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


def test_command_cyclic_detect(start_binary):
    """
    Tests the `cyclic --detect` command for:
    1. A direct value in a register.
    2. A pointer to a value on the stack.
    3. A value from a custom alphabet.
    """
    start_binary(REFERENCE_BINARY)

    ptr_size = pwndbg.aglib.arch.ptrsize
    endian = pwndbg.aglib.arch.endian

    offset_rax = 20
    pattern_default = cyclic(length=100, n=ptr_size)
    value_rax = int.from_bytes(pattern_default[offset_rax : offset_rax + ptr_size], endian)
    pwndbg.aglib.regs.rax = value_rax

    offset_rbx_ptr = 40
    stack_addr = pwndbg.aglib.regs.rsp
    pwndbg.aglib.memory.write(
        stack_addr, pattern_default[offset_rbx_ptr : offset_rbx_ptr + ptr_size]
    )
    pwndbg.aglib.regs.rbx = stack_addr

    offset_rcx = 15
    alphabet_custom = b"0123456789ABCDEF"
    pattern_custom = cyclic(length=100, n=ptr_size, alphabet=alphabet_custom)
    value_rcx = int.from_bytes(pattern_custom[offset_rcx : offset_rcx + ptr_size], endian)
    pwndbg.aglib.regs.rcx = value_rcx

    out_default = gdb.execute("cyclic --detect", to_string=True)

    out_custom = gdb.execute(f"cyclic --detect -a {alphabet_custom.decode()}", to_string=True)

    results_default = {
        parts[0]: int(parts[-1])
        for line in out_default.strip().split("\n")[2:]  # Skip header lines
        if (parts := line.split())
    }

    results_custom = {
        parts[0]: int(parts[-1])
        for line in out_custom.strip().split("\n")[2:]  # Skip header lines
        if (parts := line.split())
    }

    assert "rax" in results_default, "Pattern in RAX not detected"
    assert (
        results_default["rax"] == offset_rax
    ), f"Incorrect offset for RAX: Got {results_default['rax']}, expected {offset_rax}"

    assert "rbx->" in results_default, "Pattern pointed to by RBX not detected"
    assert (
        results_default["rbx->"] == offset_rbx_ptr
    ), f"Incorrect offset for RBX->: Got {results_default['rbx->']}, expected {offset_rbx_ptr}"

    assert "rcx" in results_custom, "Pattern in RCX with custom alphabet not detected"
    assert (
        results_custom["rcx"] == offset_rcx
    ), f"Incorrect offset for RCX: Got {results_custom['rcx']}, expected {offset_rcx}"
