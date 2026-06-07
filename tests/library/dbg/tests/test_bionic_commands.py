"""
pwndbg on a static bionic (Android libc) binary, which has no provider (scudo allocator):
the libc-agnostic commands still work, and the heap commands degrade gracefully rather
than wedge the session. x86-64 only.
"""

from __future__ import annotations

import contextlib
import platform
from pathlib import Path

import pytest

from ....host import Controller
from . import bionic_api_binaries
from . import launch_to
from . import pwndbg_test

_BIONIC_BINARIES = bionic_api_binaries()

bionic_versions = pytest.mark.parametrize(
    "binary", [b for _, b in _BIONIC_BINARIES], ids=[i for i, _ in _BIONIC_BINARIES]
)


@bionic_versions
@pwndbg_test
async def test_bionic_libc_agnostic_commands(ctrl: Controller, binary: Path) -> None:
    """pwndbg's libc-agnostic commands run and produce plausible output (addresses) on a
    static Android binary; bionic's heap and structs differ, so no exact layout is asserted."""
    # Checked before launching: the probes are prebuilt x86-64 ELFs, so on another
    # arch the launch itself fails with an exec format error before any skip.
    if platform.machine() != "x86_64":
        pytest.skip("bionic tests are x86-64 only (prebuilt x86-64 probes)")

    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    vmmap = await ctrl.execute_and_capture("vmmap")
    assert "0x" in vmmap, vmmap

    nearpc = await ctrl.execute_and_capture("nearpc")
    assert "0x" in nearpc, nearpc

    tele = await ctrl.execute_and_capture("telescope $sp")
    assert "0x" in tele, tele

    bt = await ctrl.execute_and_capture("context backtrace")
    assert "break_here" in bt or "0x" in bt, bt


@bionic_versions
@pwndbg_test
async def test_bionic_heap_commands_degrade_gracefully(ctrl: Controller, binary: Path) -> None:
    """Heap commands cannot work on bionic (no provider; scudo allocator), so they may
    error, but they must not hang or wedge the session. Tolerate the error, then assert
    pwndbg is still responsive; never assert any particular error wording."""
    if platform.machine() != "x86_64":
        pytest.skip("bionic tests are x86-64 only (prebuilt x86-64 probes)")

    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    # No bionic provider, so the glibc heap commands hit a real pwndbg robustness gap here
    # ('NoneType' object is not subscriptable), surfacing as an untyped gdb.error rather than
    # a clean pwndbg error, so the catch can't be narrowed. Tolerate any failure and only
    # require the session stays responsive (the vmmap below).
    for cmd in ("heap", "bins", "jemalloc heap"):
        with contextlib.suppress(Exception):
            await ctrl.execute_and_capture(cmd)

    # pwndbg must remain responsive after the (possibly failing) heap commands.
    vmmap = await ctrl.execute_and_capture("vmmap")
    assert "0x" in vmmap, vmmap
