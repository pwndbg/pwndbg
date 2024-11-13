from __future__ import annotations

import gdb

import pwndbg.aglib.memory
import pwndbg.aglib.stack
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_callstack_readable(start_binary):
    start_binary(REFERENCE_BINARY)
    gdb.execute("b break_here")
    gdb.execute("r")

    addresses = pwndbg.aglib.stack.callstack()

    assert len(addresses) > 0
    assert all(pwndbg.aglib.memory.is_readable_address(address) for address in addresses)
