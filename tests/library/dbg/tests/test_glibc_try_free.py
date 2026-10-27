from __future__ import annotations

from pathlib import Path

import pytest

from ....host import Controller
from . import glibc_version_binaries
from . import glibc_version_params
from . import launch_to
from . import pwndbg_test

parametrize_glibc_versions = glibc_version_params(glibc_version_binaries("heap_try_free_bin"))


@parametrize_glibc_versions
@pwndbg_test
async def test_glibc_try_free_corrupted_bin(ctrl: Controller, binary: Path) -> None:
    """
    try-free should check the bin glibc puts the chunk in: the unsorted bin
    before glibc 2.41, the chunk's smallbin since then
    """
    import pwndbg.aglib
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    import pwndbg.libc

    await launch_to(ctrl, binary, "break_here")

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("glibc version tests are x86-64/aarch64 only")

    to_free_addr = pwndbg.aglib.symbol.lookup_symbol_addr("to_free")
    assert to_free_addr is not None
    to_free = pwndbg.aglib.memory.read_pointer_width(to_free_addr)

    result = await ctrl.execute_and_capture(f"try-free {to_free:#x}")
    if pwndbg.libc.version() >= (2, 41):
        assert "free(): chunks in smallbin corrupted" in result
        assert "free(): corrupted unsorted chunks" not in result
    else:
        assert "free(): corrupted unsorted chunks" in result
        assert "free(): chunks in smallbin corrupted" not in result
