from __future__ import annotations

import tempfile
from pathlib import Path

from ....host import Controller
from . import get_binary
from . import pwndbg_test

CRASH_SIMPLE_BINARY = get_binary("crash_simple.native.out")


@pwndbg_test
async def test_is_core_file(ctrl: Controller) -> None:
    """
    Ensure Process.is_core_file() correctly distinguishes between
    a live inferior and a loaded core file.
    """
    import pwndbg

    await ctrl.launch(CRASH_SIMPLE_BINARY)

    proc = pwndbg.dbg.selected_inferior()
    assert proc is not None
    assert proc.is_core_file() is False

    await ctrl.cont()

    with tempfile.NamedTemporaryFile(delete=False) as f:
        core_path = Path(f.name)

    try:
        await ctrl.generate_core_file(Path(core_path))

        proc = pwndbg.dbg.selected_inferior()
        assert proc is not None
        assert proc.is_core_file() is True

    finally:
        if core_path.exists():
            core_path.unlink()
