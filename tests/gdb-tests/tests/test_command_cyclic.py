import gdb
from pwnlib.util.cyclic import cyclic

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_cyclic_value(start_binary):
    """
    Tests lookup on a constant value
    """
    start_binary(REFERENCE_BINARY)

    ptr_size = pwndbg.gdblib.arch.ptrsize
    test_offset = 37
    pattern = cyclic(length=80, n=ptr_size)
    val = int.from_bytes(pattern[test_offset : test_offset + ptr_size], pwndbg.gdblib.arch.endian)
    out = gdb.execute(f"cyclic -l {hex(val)}", to_string=True)

    assert int(out.split("\n")[1]) == test_offset


def test_command_cyclic_register(start_binary):
    """
    Tests lookup on a register
    """
    start_binary(REFERENCE_BINARY)

    ptr_size = pwndbg.gdblib.arch.ptrsize
    test_offset = 45
    pattern = cyclic(length=80, n=ptr_size)
    pwndbg.gdblib.regs.rdi = int.from_bytes(
        pattern[test_offset : test_offset + ptr_size], pwndbg.gdblib.arch.endian
    )
    out = gdb.execute("cyclic -l $rdi", to_string=True)

    assert int(out.split("\n")[1]) == test_offset


def test_command_cyclic_address(start_binary):
    """
    Tests lookup on a memory address
    """
    start_binary(REFERENCE_BINARY)

    addr = pwndbg.gdblib.regs.rsp
    ptr_size = pwndbg.gdblib.arch.ptrsize
    test_offset = 48
    pattern = cyclic(length=80, n=ptr_size)
    pwndbg.gdblib.memory.write(addr, pattern)
    out = gdb.execute(f"cyclic -l '{{unsigned long}}{hex(addr + test_offset)}'", to_string=True)

    assert int(out.split("\n")[1]) == test_offset
