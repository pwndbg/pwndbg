from __future__ import annotations

import gdb
from pwnlib.util.cyclic import cyclic

import pwndbg.aglib
import pwndbg.aglib.memory

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


# WARN: Function not yet ported to dbg/


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
    pattern_default = cyclic(length=100)
    value_rax = int.from_bytes(pattern_default[offset_rax : offset_rax + ptr_size], endian)
    pwndbg.aglib.regs.write_reg("rax", value_rax)

    offset_rbx_ptr = 40
    stack_addr = pwndbg.aglib.regs.sp
    pwndbg.aglib.memory.write(
        stack_addr, pattern_default[offset_rbx_ptr : offset_rbx_ptr + ptr_size]
    )
    pwndbg.aglib.regs.write_reg("rbx", stack_addr)

    offset_rcx = 15
    alphabet_custom = b"0123456789ABCDEF"
    pattern_custom = cyclic(length=100, alphabet=alphabet_custom)
    value_rcx = int.from_bytes(pattern_custom[offset_rcx : offset_rcx + ptr_size], endian)
    pwndbg.aglib.regs.write_reg("rcx", value_rcx)

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
    assert results_default["rax"] == offset_rax, (
        f"Incorrect offset for RAX: Got {results_default['rax']}, expected {offset_rax}"
    )

    assert "rbx->" in results_default, "Pattern pointed to by RBX not detected"
    assert results_default["rbx->"] == offset_rbx_ptr, (
        f"Incorrect offset for RBX->: Got {results_default['rbx->']}, expected {offset_rbx_ptr}"
    )

    assert "rcx" in results_custom, "Pattern in RCX with custom alphabet not detected"
    assert results_custom["rcx"] == offset_rcx, (
        f"Incorrect offset for RCX: Got {results_custom['rcx']}, expected {offset_rcx}"
    )
