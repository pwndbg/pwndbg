from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_flags_command(ctrl: Controller) -> None:
    import pwndbg.aglib

    await ctrl.launch(REFERENCE_BINARY)

    arch = pwndbg.aglib.arch.name

    match arch:
        case "i386" | "x86-64":
            register_name = "eflags"
            flag_name = "cf"
            flag_bit = 1
        case "aarch64":
            register_name = "cpsr"
            flag_name = "c"
            flag_bit = 1 << 29
        case _:
            pytest.skip(f"Architechture {arch} not supported.")

    old_flags = pwndbg.aglib.regs.read_reg(register_name)
    if old_flags is None:
        pytest.skip(f"{register_name} register is missing")

    await ctrl.execute(f"setflag {flag_name} 0")

    # Verify CF is not set
    assert old_flags & flag_bit == 0

    await ctrl.execute(f"setflag {flag_name} 1")

    # Verify CF is set and no other flags have changed
    assert (old_flags | flag_bit) == pwndbg.aglib.regs.read_reg(register_name)

    await ctrl.execute(f"setflag {flag_name} 0")

    # Verify CF is not set and no other flags have changed
    assert old_flags & flag_bit == 0

    # Test setting an invalid value
    await ctrl.execute(f"setflag {flag_name} 2")

    # Verify no flags have changed
    assert old_flags == pwndbg.aglib.regs.read_reg(register_name)
