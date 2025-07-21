from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")


@pwndbg_test
async def test_callstack_readable(ctrl: Controller) -> None:
    import pwndbg.aglib.memory
    import pwndbg.aglib.stack

    await launch_to(ctrl, REFERENCE_BINARY, "break_here")

    addresses = pwndbg.aglib.stack.callstack()

    assert len(addresses) > 0
    assert all(pwndbg.aglib.memory.is_readable_address(address) for address in addresses)
