from __future__ import annotations

import pytest

from . import get_binary
from . import launch_to
from . import pwndbg_test

CANARY_X86_64_BINARY = get_binary("canary.x86-64.out")
CANARY_I386_BINARY = get_binary("canary.i386.out")


@pwndbg_test
@pytest.mark.integration
@pytest.mark.parametrize(
    "binary, reg_name, skips",
    [
        (CANARY_X86_64_BINARY, "rax", 0),
        (CANARY_I386_BINARY, "eax", 2),
    ],
    ids=["x86-64", "i386"],
)
async def test_command_canary(ctrl: Controller, binary: str, reg_name: str, skips: int) -> None:
    """
    Tests the canary command for x86-64 and i386 architectures
    """
    import pwndbg
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs

    await launch_to(ctrl, binary, "main")

    # The instruction that loads the canary is at the start of the function,
    # but it it not necessarily at any given fixed position, scan for it.
    initial_reg = getattr(pwndbg.aglib.regs, reg_name)
    while True:
        register = getattr(pwndbg.aglib.regs, reg_name)
        if register != initial_reg:
            if skips == 0:
                break
            skips = skips - 1
            initial_reg = register

        await ctrl.step_instruction()

    canary_value, at_random = pwndbg.commands.canary.canary_value()

    raw = pwndbg.aglib.memory.read_pointer_width(at_random)
    mask = pwndbg.aglib.arch.ptrmask ^ 0xFF
    masked_raw = raw & mask

    tls_addr = pwndbg.commands.canary.find_tls_canary_addr()
    raw_tls = pwndbg.aglib.memory.read_pointer_width(tls_addr) & mask

    # Check AT_RANDOM
    assert masked_raw == canary_value
    # Check TLS Canary
    assert raw_tls == canary_value
    # Check Canary
    assert register == canary_value
