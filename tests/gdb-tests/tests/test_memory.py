from __future__ import annotations

import gdb

import pwndbg.gdblib.memory
import pwndbg.gdblib.stack
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")
NESTED_STRUCTS_BINARY = tests.binaries.get("nested_structs.out")


def test_memory_read_write(start_binary):
    """
    Tests simple pwndbg's memory read/write operations with different argument types
    """
    start_binary(REFERENCE_BINARY)
    stack_addr = next(iter(pwndbg.gdblib.stack.get().values())).vaddr

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


def test_fetch_struct_as_dictionary(start_binary):
    """
    Test pwndbg.gdblib.memory.fetch_struct_as_dictionary()
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

    struct_address = pwndbg.gdblib.symbol.address("outer")
    assert struct_address is not None

    result = pwndbg.gdblib.memory.fetch_struct_as_dictionary("outer_struct", struct_address)

    assert result == expected_result


def test_fetch_struct_as_dictionary_include_filter(start_binary):
    """
    Test pwndbg.gdblib.memory.fetch_struct_as_dictionary()
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

    struct_address = pwndbg.gdblib.symbol.address("outer")
    assert struct_address is not None

    result = pwndbg.gdblib.memory.fetch_struct_as_dictionary(
        "outer_struct",
        struct_address,
        include_only_fields={"outer_x", "inner", "anonymous_k", "anonymous_nested"},
    )

    assert result == expected_result


def test_fetch_struct_as_dictionary_exclude_filter(start_binary):
    """
    Test pwndbg.gdblib.memory.fetch_struct_as_dictionary()
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

    struct_address = pwndbg.gdblib.symbol.address("outer")
    assert struct_address is not None

    result = pwndbg.gdblib.memory.fetch_struct_as_dictionary(
        "outer_struct",
        struct_address,
        exclude_fields={"outer_x", "inner", "outer_z"},
    )

    assert result == expected_result
