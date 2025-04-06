from __future__ import annotations

import pwndbg.aglib.memory
import pwndbg.aglib.stack


def test_callstack_readable():
    addresses = list(pwndbg.aglib.stack.callstack())

    assert len(addresses) > 0
    assert all(pwndbg.aglib.memory.is_readable_address(address) for address in addresses)


def test_callstack_with_symbols():
    for addr, symbol in pwndbg.aglib.stack.callstack_with_symbols():
        assert pwndbg.aglib.memory.is_readable_address(addr)
        assert symbol is None or isinstance(symbol, str)