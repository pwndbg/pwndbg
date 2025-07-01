from __future__ import annotations

from host import Controller

import tests

REFERENCE_BINARY = tests.get_binary("reference-binary.out")


@tests.pwndbg_test
async def test_callstack_readable(ctrl: Controller) -> None:
    import pwndbg.aglib.memory
    import pwndbg.aglib.stack

    await tests.launch_to(ctrl, REFERENCE_BINARY, "break_here")

    addresses = pwndbg.aglib.stack.callstack()

    assert len(addresses) > 0
    assert all(pwndbg.aglib.memory.is_readable_address(address) for address in addresses)
