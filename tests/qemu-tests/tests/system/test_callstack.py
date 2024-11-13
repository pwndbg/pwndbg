from __future__ import annotations

import pwndbg.aglib.memory
import pwndbg.aglib.stack


def test_callstack_readable():
    addresses = pwndbg.aglib.stack.callstack()

    assert len(addresses) > 0
    assert all(pwndbg.aglib.memory.is_readable_address(address) for address in addresses)
