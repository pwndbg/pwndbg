from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

MUSL_DYNAMIC = get_binary("heap_musl_dyn.native.out")
MUSL_STATIC = get_binary("heap_musl_static.native.out")


@pwndbg_test
async def test_musl_dynamic_detection(ctrl: Controller) -> None:
    import pwndbg.libc

    ctrl.disable_debuginfod()

    await launch_to(ctrl, MUSL_DYNAMIC, "main")

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.MUSL

    # This stops on _dlstart.
    await ctrl.launch(MUSL_DYNAMIC)
    # This wouldn't work for glibc because the libc shared library wouldn't have been loaded yet,
    # but does for musl, because the libc and the ld are the same file.
    assert pwndbg.libc.which() == pwndbg.libc.LibcType.MUSL

    # Sanity check some stuff we expect from musl
    assert pwndbg.libc.filepath() == pwndbg.libc.loader_filepath()
    assert pwndbg.libc.addr() == pwndbg.libc.loader_addr() != 0
    assert pwndbg.libc.has_exported_symbols()
    assert not pwndbg.libc.has_internal_symbols()
    assert not pwndbg.libc.has_debug_info()


@pwndbg_test
async def test_musl_static_detection(ctrl: Controller) -> None:
    import pwndbg.libc

    ctrl.disable_debuginfod()

    await launch_to(ctrl, MUSL_STATIC, "main")

    # I'd be happy to see this test updated :>
    assert pwndbg.libc.which() == pwndbg.libc.LibcType.UNKNOWN

    await ctrl.launch(MUSL_STATIC)
    # I'd be happy to see this test updated :>
    assert pwndbg.libc.which() == pwndbg.libc.LibcType.UNKNOWN

    # Sanity check that we can still resolve the important info.
    assert pwndbg.libc.filepath() == pwndbg.libc.loader_filepath()
    assert pwndbg.libc.addr() == pwndbg.libc.loader_addr() != 0
    assert not pwndbg.libc.has_exported_symbols()
    assert not pwndbg.libc.has_internal_symbols()
    assert not pwndbg.libc.has_debug_info()
