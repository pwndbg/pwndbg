import pwndbg.gdblib.memory
import pwndbg.gdblib.stack
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_memory_read_write(start_binary):
    """
    Tests simple pwndbg's memory read/write operations with different argument types
    """
    start_binary(REFERENCE_BINARY)
    stack_addr = next(iter(pwndbg.gdblib.stack.stacks.values())).vaddr

    # Testing write(addr, str)
    val = "X" * 50
    pwndbg.gdblib.memory.write(stack_addr, val)
    assert pwndbg.gdblib.memory.read(stack_addr, len(val) + 1) == bytearray(b"X" * 50 + b"\x00")

    # Testing write(addr, bytearray)
    val = bytearray("Y" * 10, "utf8")
    pwndbg.gdblib.memory.write(stack_addr, val)
    assert pwndbg.gdblib.memory.read(stack_addr, len(val) + 4) == val + bytearray(b"XXXX")

    # Testing write(addr, bytes)
    val = bytes("Z" * 8, "utf8")
    pwndbg.gdblib.memory.write(stack_addr, val)
    assert pwndbg.gdblib.memory.read(stack_addr, len(val) + 4) == bytearray(
        "Z" * 8 + "YYXX", "utf8"
    )
