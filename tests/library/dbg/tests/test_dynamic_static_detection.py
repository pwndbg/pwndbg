from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

DYNAMIC = get_binary("heap_musl_dyn.native.out")
STATIC = get_binary("heap_musl_static.native.out")

# Regression test for #3643


@pwndbg_test
async def test_dynamic_detection(ctrl: Controller) -> None:
    import pwndbg

    await ctrl.disable_debuginfod()

    await launch_to(ctrl, DYNAMIC, "main")

    assert pwndbg.dbg.selected_inferior().is_dynamically_linked()


@pwndbg_test
async def test_static_detection(ctrl: Controller) -> None:
    import pwndbg

    await ctrl.disable_debuginfod()

    await launch_to(ctrl, STATIC, "main")

    assert not pwndbg.dbg.selected_inferior().is_dynamically_linked()
