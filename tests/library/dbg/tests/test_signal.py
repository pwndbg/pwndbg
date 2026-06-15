from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

PKU_BINARY = get_binary("pku.x86-64.out")


@pwndbg_test
async def test_pku(ctrl: Controller) -> None:
    """
    Test that PKU-related memory access violations are properly reported.
    """
    import pwndbg

    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()
            if "pku" not in cpuinfo:
                pytest.skip("PKU not supported on this CPU")
    except FileNotFoundError:
        pytest.skip("Cannot determine PKU support (/proc/cpuinfo not found)")

    await ctrl.launch(PKU_BINARY)
    await ctrl.execute("set context-sections last_signal")
    await ctrl.cont()
    output = await ctrl.execute_and_capture("ctx")

    assert output is not None
    assert "Program received signal SEGV_PKUERR (fault address: 0x" in output
    if pwndbg.dbg.is_gdblib_available():
        assert "Violated protection key 1(AD=0, WD=1)" in output
