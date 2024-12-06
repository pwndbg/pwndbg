from __future__ import annotations

import gdb

import pwndbg.dbg
import tests

MANGLING_BINARY = tests.binaries.get("symbol_1600_and_752.out")


def test_symbol_get(start_binary):
    start_binary(MANGLING_BINARY)
    gdb.execute("break break_here")

    def get_next_ptr():
        gdb.execute("continue")

        # To fetch the value of 'p' it must be set first
        # and it will be set by the program copying from register to the stack
        # (we pass `to_string=True` to suppress the context output)
        gdb.execute("nextret", to_string=True)
        p = int(gdb.parse_and_eval("p"))
        return pwndbg.dbg.selected_inferior().symbol_name_at_address(p)

    assert get_next_ptr() == "main"

    assert get_next_ptr() == "break_here(void*)"

    # Test for the bug https://github.com/pwndbg/pwndbg/issues/1600
    assert get_next_ptr() == "A::foo(int, int)"

    assert get_next_ptr() == "A::call_foo()"


def test_symbol_duplicated_symbols_issue_1610():
    """
    Test for the bug from https://github.com/pwndbg/pwndbg/issues/1610
    """
    gdb.execute(f"file {MANGLING_BINARY}")

    main_addr = int(gdb.parse_and_eval("(unsigned long long)main"))

    # Sanity checks
    assert gdb.execute("info symbol main", to_string=True) == "main in section .text\n"
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"

    # This causes some confusion, see below :)
    # Note: {addr} argument is needed for old GDB (e.g. on Ubuntu 18.04)
    addr = _get_section_addr(".text")
    gdb.execute(f"add-symbol-file {MANGLING_BINARY} {addr}")

    # Sanity check - yeah, there are two symbols
    out = gdb.execute("info symbol main", to_string=True).split("\n")

    assert len(out) == 3

    assert out[0] == out[1]
    assert out[0].startswith("main in section .text of ")

    assert out[2] == ""

    # Make sure to clear cache!
    # TODO: clear cache
    # from pwndbg.aglib.symbol import lookup_symbol_value
    # lookup_symbol_value.cache.clear()

    # Real test assert - this should not crash!
    assert pwndbg.dbg.selected_inferior().symbol_name_at_address(main_addr) == "main"


def _get_section_addr(sect):
    result = gdb.execute("maintenance info sections", to_string=True).split("\n")
    text_line = next(line for line in result if f": {sect} " in line)
    return int(text_line.split(" at ")[1].split(":")[0], 16)
