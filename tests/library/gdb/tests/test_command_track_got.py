from __future__ import annotations

import platform
import re

import gdb
import pytest

import pwndbg.aglib.vmmap
import pwndbg.gdblib.got

from . import get_binary

PLT_BINARY = get_binary("reference-binary-plt.native.out")

# Rows of `track-got info` look like:
# 0x555555557fd0 0x7ffff7c80e50 puts 1 hit
ROW_RE = re.compile(r"^(0x[0-9a-f]+) +(0x[0-9a-f]+) +(\S+) +(\d+) hits?$", re.MULTILINE)


# The trap allocator of the GOT tracker runs shellcode in the inferior, which
# currently fails to restore the registers on aarch64.
@pytest.mark.skipif(platform.machine() != "x86_64", reason="track-got is only tested on x86-64")
def test_track_got_tracks_jump_and_irelative_slots(start_binary):
    """
    Between the first two calls to break_here() the binary calls puts() and
    printf(). Those go through the jump slot in the binary's GOT and, inside
    libc, through the anonymous (IRELATIVE) GOT slots of ifunc-resolved
    functions like strlen(). Both kinds of entries must be tracked.
    """
    start_binary(PLT_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    gdb.execute("track-got enable")
    try:
        gdb.execute("continue")

        info = gdb.execute("track-got info", to_string=True)
        rows = {(name, int(hits)) for _, _, name, hits in ROW_RE.findall(info)}
        names = {name for name, _ in rows}

        # Jump slots are still tracked as before.
        assert ("puts", 1) in rows

        # Anonymous slots show up under their resolver address, as in `got`.
        anonymous = {name for name in names if name.startswith("*ABS*+0x")}
        assert anonymous, info
        assert "<Empty>" not in names

        # ...and calls made through them are counted.
        assert any(name in anonymous and hits > 0 for name, hits in rows), info

        # The addend of an IRELATIVE entry must not have been added to the
        # address of the slot: every tracked entry must be in a mapped page.
        for address, _ in pwndbg.gdblib.got.all_tracked_entries():
            assert pwndbg.aglib.vmmap.find(address) is not None, f"{address:#x} is not mapped"

        # `track-got query` uses the same name for anonymous entries.
        address = next(
            address
            for address, (tracker, _) in pwndbg.gdblib.got.all_tracked_entries()
            if tracker.sym_display_name.startswith("*ABS*+0x")
        )
        query = gdb.execute(f"track-got query {address:#x}", to_string=True)
        assert "Tracking details for *ABS*+0x" in query
    finally:
        gdb.execute("track-got disable")
