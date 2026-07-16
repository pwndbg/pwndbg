from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("heap_tracker_realloc_fail.native.out")


@pwndbg_test
async def test_track_heap_survives_realloc_failure(ctrl: Controller) -> None:
    """A realloc() that returns NULL must not crash the tracker (#3998).

    The binary does `realloc(p, (size_t)-1)`, which the allocator cannot satisfy
    and so returns NULL, leaving the original block valid. The tracker used to
    feed that NULL through get_chunk(), reading a header at `0 - sizeof(void*)`
    and raising an uncaught `Cannot access memory at address 0xfffffffffffffff8`.
    """
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.GDB:
        pytest.skip("track-heap hooks a GDB-only event (inferior_call_post)")
        return

    await launch_to(ctrl, REFERENCE_BINARY, "main")

    await ctrl.execute("track-heap enable")
    output = await ctrl.execute_and_capture("continue")

    # The failed realloc must not surface as a Python exception / crash.
    assert "Cannot access memory" not in output
    assert "Exception" not in output
    assert "Traceback" not in output

    # It is reported as returning NULL rather than a real chunk...
    assert "realloc(" in output
    assert "-> 0x0" in output

    # ...and the tracker is left in a good state: the original block is still
    # tracked, so the subsequent free() is recognised (not flagged as an
    # unknown / previously-unseen pointer).
    assert "free(" in output
    assert "previously unknown pointer" not in output
