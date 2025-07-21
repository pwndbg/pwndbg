from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")


@pwndbg_test
async def test_flags_command(ctrl: Controller) -> None:
    import pwndbg.aglib.regs

    await ctrl.launch(REFERENCE_BINARY)

    old_eflags = pwndbg.aglib.regs.eflags

    # Verify CF is not set
    assert old_eflags & 0x1 == 0

    await ctrl.execute("setflag cf 1")

    # Verify CF is set and no other flags have changed
    assert (old_eflags | 1) == pwndbg.aglib.regs.eflags

    await ctrl.execute("setflag cf 0")

    # Verify CF is not set and no other flags have changed
    assert old_eflags == pwndbg.aglib.regs.eflags

    # Test setting an invalid value
    await ctrl.execute("setflag cf 2")

    # Verify no flags have changed
    assert old_eflags == pwndbg.aglib.regs.eflags
