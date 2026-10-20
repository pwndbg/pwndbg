from __future__ import annotations

import gdb

import pwndbg

from . import get_binary

WEIRD_SYMBOLS_BINARY = get_binary("weird_symbols.native.out")


def test_symbol_duplicated_symbols_issue_1610():
    """
    Test for the bug from https://github.com/pwndbg/pwndbg/issues/1610
    """
    gdb.execute(f"file {WEIRD_SYMBOLS_BINARY}")

    main_addr = int(gdb.parse_and_eval("(unsigned long long)main"))

    # Sanity checks
    assert gdb.execute("info symbol main", to_string=True) == "main in section .text\n"
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"

    # This causes some confusion, see below :)
    # Note: {addr} argument is needed for old GDB (e.g. on Ubuntu 18.04)
    addr = _get_section_addr(".text")
    gdb.execute(f"add-symbol-file {WEIRD_SYMBOLS_BINARY} {addr}")

    # Sanity check - yeah, there are two symbols
    out = gdb.execute("info symbol main", to_string=True).split("\n")

    assert len(out) == 3

    assert out[0] == out[1]
    assert out[0].startswith("main in section .text of ")

    assert out[2] == ""

    # Make sure to clear cache!
    # TODO: clear cache
    # from pwndbg.aglib.symbol import lookup_symbol_value
    # pwndbg.lib.cache.clear_function_cache(lookup_symbol_value)

    # Real test assert - this should not crash!
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"


def _get_section_addr(sect):
    result = gdb.execute("maintenance info sections", to_string=True).split("\n")
    text_line = next(line for line in result if f": {sect} " in line)
    return int("0x" + text_line.split("->")[0].split("0x")[1], 16)
