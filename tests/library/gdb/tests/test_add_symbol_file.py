from __future__ import annotations

import gdb

import pwndbg

from . import get_binary

MANGLING_BINARY = get_binary("symbol_1600_and_752.native.out")


def _get_section_addr(sect):
    result = gdb.execute("maintenance info sections", to_string=True).split("\n")
    text_line = next(line for line in result if f": {sect} " in line)
    return int("0x" + text_line.split("->")[0].split("0x")[1], 16)


def test_add_symbol_file_without_base(start_binary):
    """
    Test add_symbol_file method without base address.
    """
    start_binary(MANGLING_BINARY)

    main_addr = int(gdb.parse_and_eval("(unsigned long long)main"))

    # Verify main symbol exists
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"

    # Add symbol file without base address
    pwndbg.dbg.selected_inferior().add_symbol_file(MANGLING_BINARY)

    # Verify the symbol file was added (we should still be able to resolve main)
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"


def test_add_symbol_file_with_base(start_binary):
    """
    Test add_symbol_file method with base address.
    """
    start_binary(MANGLING_BINARY)

    main_addr = int(gdb.parse_and_eval("(unsigned long long)main"))

    # Verify main symbol exists
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"

    # Get the .text section address
    text_addr = _get_section_addr(".text")

    # Add symbol file with base address
    pwndbg.dbg.selected_inferior().add_symbol_file(MANGLING_BINARY, text_addr)

    # Verify the symbol file was added (we should still be able to resolve main)
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"


def test_remove_symbol_file(start_binary):
    """
    Test remove_symbol_file method.
    """
    start_binary(MANGLING_BINARY)

    main_addr = int(gdb.parse_and_eval("(unsigned long long)main"))

    # Verify main symbol exists
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"

    # Add symbol file first
    text_addr = _get_section_addr(".text")
    pwndbg.dbg.selected_inferior().add_symbol_file(MANGLING_BINARY, text_addr)

    # Remove the symbol file
    result = pwndbg.dbg.selected_inferior().remove_symbol_file(MANGLING_BINARY)

    # Verify removal succeeded (returns True)
    assert result is True

    # Verify we can still resolve main (the original binary is still loaded)
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"


def test_remove_symbol_file_not_found(start_binary):
    """
    Test remove_symbol_file method with a file that was never added.
    """
    start_binary(MANGLING_BINARY)

    # Try to remove a symbol file that was never added
    result = pwndbg.dbg.selected_inferior().remove_symbol_file("/nonexistent/path/to/file")

    # Verify removal failed (returns False)
    assert result is False
