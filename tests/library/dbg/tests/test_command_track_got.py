from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

PLT_BINARY = get_binary("reference-binary-plt.native.out")

# Rows of `track-got info` look like:
# 0x555555557fd0 0x7ffff7c80e50 puts 1 hit
ROW_RE = re.compile(r"^(0x[0-9a-f]+) +(0x[0-9a-f]+) +(\S+) +(\d+) hits? *$", re.MULTILINE)


@pwndbg_test
async def test_track_got_tracks_jump_and_irelative_slots(ctrl: Controller) -> None:
    """
    Between the first two calls to break_here() the binary calls puts() and
    printf(). Those go through the jump slot in the binary's GOT and, inside
    libc, through the anonymous (IRELATIVE) GOT slots of ifunc-resolved
    functions like strlen(). Both kinds of entries must be tracked.
    """
    import pwndbg
    import pwndbg.aglib
    import pwndbg.aglib.vmmap
    import pwndbg.color
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.GDB:
        pytest.skip("track-got is a GDB-only command")
        return

    # The trap allocator of the GOT tracker runs shellcode in the inferior,
    # which currently fails to restore the registers on aarch64.
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("track-got is only tested on x86-64")
        return

    await launch_to(ctrl, PLT_BINARY, "break_here")
    # Enabling the tracker runs code in the inferior, after which the debugger
    # would report the breakpoint we are stopped at again instead of resuming
    # past it. So return to main first, where there is no breakpoint.
    await ctrl.finish()

    await ctrl.execute("track-got enable")
    try:
        # Run until the second call to break_here().
        await ctrl.cont()

        info = pwndbg.color.strip(await ctrl.execute_and_capture("track-got info"))
        entries = [
            (int(address, 16), name, int(hits)) for address, _, name, hits in ROW_RE.findall(info)
        ]
        rows = {(name, hits) for _, name, hits in entries}
        names = {name for name, _ in rows}

        # Jump slots are still tracked as before.
        assert ("puts", 1) in rows, info

        # Anonymous slots show up under their resolver address, as in `got`.
        anonymous = {name for name in names if name.startswith("*ABS*+0x")}
        assert anonymous, info
        assert "<Empty>" not in names

        # ...and calls made through them are counted.
        assert any(name in anonymous and hits > 0 for name, hits in rows), info

        # The addend of a relocation must not have been added to the address
        # of its slot: every tracked entry must be in a mapped page.
        for address, _, _ in entries:
            assert pwndbg.aglib.vmmap.find(address) is not None, f"{address:#x} is not mapped"

        # `track-got query` uses the same name for anonymous entries.
        address = next(address for address, name, _ in entries if name in anonymous)
        query = await ctrl.execute_and_capture(f"track-got query {address:#x}")
        assert "Tracking details for *ABS*+0x" in query
    finally:
        await ctrl.execute("track-got disable")
