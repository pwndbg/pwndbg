import gdb

import pwndbg
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
        return pwndbg.gdblib.symbol.get(p)

    assert get_next_ptr() == "main"

    assert get_next_ptr() == "break_here(void*)"

    # Test for the bug https://github.com/pwndbg/pwndbg/issues/1600
    assert get_next_ptr() == "A::foo(int, int)"

    assert get_next_ptr() == "A::call_foo()"
