from __future__ import annotations

import pwndbg.gdblib.memory
import pwndbg.gdblib.stack


def test_callstack_readable():
    addresses = pwndbg.gdblib.stack.callstack()

    assert len(addresses) > 0
    assert all(pwndbg.gdblib.memory.is_readable_address(address) for address in addresses)
