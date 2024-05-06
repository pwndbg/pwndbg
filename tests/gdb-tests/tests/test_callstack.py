from __future__ import annotations

import gdb

import pwndbg.gdblib.memory
import pwndbg.gdblib.stack
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_callstack_readable(start_binary):
    start_binary(REFERENCE_BINARY)
    gdb.execute("b break_here")
    gdb.execute("r")

    addresses = pwndbg.gdblib.stack.callstack()

    assert len(addresses) > 0
    assert all(pwndbg.gdblib.memory.is_readable_address(address) for address in addresses)
