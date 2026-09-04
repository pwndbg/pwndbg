from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("heap_tracker_symbols.native.out")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _annotation_after(lines: list[str], marker: str) -> str:
    """Return the (stripped) line immediately following the first line containing `marker`."""
    for i, line in enumerate(lines):
        if marker in line:
            return lines[i + 1].strip()
    raise AssertionError(f"no line containing {marker!r} found in output:\n" + "\n".join(lines))


@pwndbg_test
async def test_track_heap_symbols_annotates_caller(ctrl: Controller) -> None:
    """`track-heap enable --where` annotates malloc, realloc, and free with the calling symbol (#3092)."""
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.GDB:
        pytest.skip("track-heap hooks a GDB-only event (inferior_call_post)")
        return

    await launch_to(ctrl, REFERENCE_BINARY, "main")

    await ctrl.execute("track-heap enable --where")
    output = _ANSI.sub("", await ctrl.execute_and_capture("continue")).splitlines()

    assert _annotation_after(output, "[*] malloc(").startswith("@ do_alloc")
    assert _annotation_after(output, "[*] realloc(").startswith("@ do_realloc")
    assert _annotation_after(output, "[*] free(").startswith("@ main")


@pwndbg_test
async def test_track_heap_without_symbols_is_unchanged(ctrl: Controller) -> None:
    """Default output must not carry the `@` annotation."""
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.GDB:
        pytest.skip("track-heap hooks a GDB-only event (inferior_call_post)")
        return

    await launch_to(ctrl, REFERENCE_BINARY, "main")

    await ctrl.execute("track-heap enable")
    output = await ctrl.execute_and_capture("continue")

    assert "@" not in output


@pwndbg_test
async def test_track_heap_failed_realloc_preserves_original_allocation(
    ctrl: Controller,
) -> None:
    import pwndbg
    import pwndbg.aglib.proc
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.GDB:
        pytest.skip("track-heap hooks a GDB-only event (inferior_call_post)")
        return

    await launch_to(ctrl, REFERENCE_BINARY, "main")

    await ctrl.execute("track-heap enable")
    output = await ctrl.execute_and_capture("continue")

    assert not pwndbg.aglib.proc.alive()
    assert "[*] free(" in output
