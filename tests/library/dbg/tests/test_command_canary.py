from __future__ import annotations

from pathlib import Path

import pytest

from ....host import Controller
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
async def test_command_canary(ctrl: Controller, binary: Path, reg_name: str, skips: int) -> None:
    """
    Tests the canary command for x86-64 and i386 architectures
    """
    import pwndbg
    import pwndbg.aglib
    import pwndbg.aglib.memory
    import pwndbg.commands.canary
    import pwndbg.libc

    await launch_to(ctrl, binary, "main")

    # The instruction that loads the canary is at the start of the function,
    # but it it not necessarily at any given fixed position, scan for it.
    initial_reg = pwndbg.aglib.regs.read_reg(reg_name)
    while True:
        register = pwndbg.aglib.regs.read_reg(reg_name)
        if register != initial_reg:
            if skips == 0:
                break
            skips = skips - 1
            initial_reg = register

        await ctrl.step_instruction()

    mask: int = pwndbg.aglib.arch.ptrmask ^ 0xFF

    tls_addr = pwndbg.commands.canary.find_tls_canary_addr()
    assert tls_addr is not None
    raw_tls = pwndbg.aglib.memory.read_pointer_width(tls_addr) & mask

    canary_value = pwndbg.commands.canary.canary_value()

    # Check TLS Canary
    assert raw_tls == canary_value
    # Check Canary
    assert register == canary_value

    at_random_canary, at_random = pwndbg.commands.canary.canary_from_at_random()
    assert at_random is not None

    if pwndbg.libc.version() < (2, 44):
        # Check AT_RANDOM, if glibc >= 2.44, at_random_canary != canary_value
        assert at_random_canary is not None
        raw = pwndbg.aglib.memory.read_pointer_width(at_random)
        masked_raw = raw & mask
        assert masked_raw == at_random_canary
        assert at_random_canary == canary_value

