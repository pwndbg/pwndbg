from __future__ import annotations

import gdb

import pwndbg.aglib.memory
import pwndbg.aglib.stack
import pwndbg.aglib.symbol
import pwndbg.dbg
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")
NESTED_STRUCTS_BINARY = tests.binaries.get("nested_structs.out")


def test_memory_read_write(start_binary):
    """
    Tests simple pwndbg's memory read/write operations with different argument types
    """
    start_binary(REFERENCE_BINARY)
    stack_addr = next(iter(pwndbg.aglib.stack.get().values())).vaddr

    # Testing write(addr, str)
    val = "X" * 50
    pwndbg.aglib.memory.write(stack_addr, val)
    assert pwndbg.aglib.memory.read(stack_addr, len(val) + 1) == bytearray(b"X" * 50 + b"\x00")

    # Testing write(addr, bytearray)
    val = bytearray("Y" * 10, "utf8")
    pwndbg.aglib.memory.write(stack_addr, val)
    assert pwndbg.aglib.memory.read(stack_addr, len(val) + 4) == val + bytearray(b"XXXX")

    # Testing write(addr, bytes)
    val = bytes("Z" * 8, "utf8")
    pwndbg.aglib.memory.write(stack_addr, val)
    assert pwndbg.aglib.memory.read(stack_addr, len(val) + 4) == bytearray("Z" * 8 + "YYXX", "utf8")


def test_memory_peek_poke(start_binary):
    """
    This tests ensures that doing a peek, poke, peek round-robin operations
    ends up with the same value in memory.
    It also sets a given byte in memory via memory.write
    and tests all single-byte values.
    """
    start_binary(REFERENCE_BINARY)

    # Address 0 is not mapped, so peek should return None
    # and poke should fail
    assert pwndbg.aglib.memory.poke(0) is False
    assert pwndbg.aglib.memory.peek(0) is None

    stack_addr = pwndbg.aglib.regs.rsp

    for v in range(256):
        data = bytearray([v, 0, 0, 0])
        pwndbg.aglib.memory.write(stack_addr, data)

        # peek should return the first byte
        assert pwndbg.aglib.memory.peek(stack_addr) == bytearray([v])

        # Now poke it!
        assert pwndbg.aglib.memory.poke(stack_addr) is True

        # Now make sure poke did not change the underlying bytes
        assert pwndbg.aglib.memory.read(stack_addr, 4) == data

    # TODO/FIXME: Fix peek/poke exception handling and uncomment this!
    """
    # Ensure that peek and poke correctly raises exceptions
    # when incorrect argument type is passed
    for not_parsable_as_int in (b"asdf", "asdf"):
        with pytest.raises(ValueError):
            pwndbg.aglib.memory.peek(not_parsable_as_int)

    for not_parsable_as_int in (b"asdf", "asdf"):
        with pytest.raises(ValueError):
            pwndbg.aglib.memory.poke(not_parsable_as_int)
    """

    # Acceptable inputs (not great; maybe we should ban them?)
    # Note: they return 0 because the address 0 is not mapped
    assert pwndbg.aglib.memory.peek(0.0) is None
    assert pwndbg.aglib.memory.peek("0") is None
    assert pwndbg.aglib.memory.peek(b"0") is None


def test_fetch_struct_as_dictionary(start_binary):
    """
    Test pwndbg.aglib.memory.fetch_struct_as_dictionary()
    Ensure it can handle nested structs, anonymous structs & nested typedefs.
    """
    start_binary(NESTED_STRUCTS_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    expected_result = {
        "outer_x": 1,
        "outer_y": 2,
        "inner": {"inner_a": 3, "inner_b": 4, "anonymous_i": 42, "anonymous_j": 44},
        "anonymous_k": 82,
        "anonymous_l": 84,
        "anonymous_nested": 100,
        "outer_z": 5,
    }

    struct_address = pwndbg.aglib.symbol.lookup_symbol_addr("outer")
    assert struct_address is not None

    result = pwndbg.aglib.memory.fetch_struct_as_dictionary("outer_struct", struct_address)

    assert result == expected_result


def test_fetch_struct_as_dictionary_include_filter(start_binary):
    """
    Test pwndbg.aglib.memory.fetch_struct_as_dictionary()
    Ensure its include_only_fields filter works.
    """
    start_binary(NESTED_STRUCTS_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    expected_result = {
        "outer_x": 1,
        "inner": {"inner_a": 3, "inner_b": 4, "anonymous_i": 42, "anonymous_j": 44},
        "anonymous_k": 82,
        "anonymous_nested": 100,
    }

    struct_address = pwndbg.aglib.symbol.lookup_symbol_addr("outer")
    assert struct_address is not None

    result = pwndbg.aglib.memory.fetch_struct_as_dictionary(
        "outer_struct",
        struct_address,
        include_only_fields={"outer_x", "inner", "anonymous_k", "anonymous_nested"},
    )

    assert result == expected_result


def test_fetch_struct_as_dictionary_exclude_filter(start_binary):
    """
    Test pwndbg.aglib.memory.fetch_struct_as_dictionary()
    Ensure its exclude_fields filter works.
    Note that the exclude filter cannot filter fields of anonymous structs.
    """
    start_binary(NESTED_STRUCTS_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    expected_result = {
        "outer_y": 2,
        "anonymous_k": 82,
        "anonymous_l": 84,
        "anonymous_nested": 100,
    }

    struct_address = pwndbg.aglib.symbol.lookup_symbol_addr("outer")
    assert struct_address is not None

    result = pwndbg.aglib.memory.fetch_struct_as_dictionary(
        "outer_struct",
        struct_address,
        exclude_fields={"outer_x", "inner", "outer_z"},
    )

    assert result == expected_result
