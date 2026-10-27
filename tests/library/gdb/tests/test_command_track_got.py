from __future__ import annotations

import re

import gdb

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")
TRACK_GOT_BINARY = get_binary("track_got.native.out")


def test_command_track_got_irelative(start_binary):
    """
    Tests that calls made through the anonymous IRELATIVE GOT slots of libc are tracked
    """
    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("continue")
    gdb.execute("stepi")

    gdb.execute("track-got enable")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # puts() calls strlen() through an *ABS*+0x...@plt stub of libc
    out = gdb.execute(r"track-got info -s .*libc -f \*ABS\*", to_string=True)
    assert re.search(r"\*ABS\*\+0x[0-9a-f]+ +[1-9][0-9]* hits?", out), out


def got_hits(fnname: str) -> list[tuple[int, int]]:
    """
    Returns the (GOT entry address, call count) of every tracked entry of the binary named fnname
    """
    out = gdb.execute(rf"track-got info -s .*track_got -f {fnname}$", to_string=True)
    return [
        (int(addr, 16), int(hits))
        for addr, hits in re.findall(
            rf"^(0x[0-9a-f]+) +0x[0-9a-f]+ +{fnname} +(\d+) hits?", out, re.MULTILINE
        )
    ]


def test_command_track_got_call_count(start_binary):
    """
    Tests that the tracker counts every call made through a GOT entry
    """
    start_binary(TRACK_GOT_BINARY)
    gdb.execute("break main")
    gdb.execute("continue")
    # Step off the breakpoint without entering a call before enabling the tracker
    gdb.execute("next")

    gdb.execute("track-got enable")
    gdb.execute("break break_here")
    assert [hits for _, hits in got_hits("puts")] == [0]
    assert [hits for _, hits in got_hits("srand")] == [0]

    gdb.execute("continue")
    assert [hits for _, hits in got_hits("puts")] == [3]
    assert [hits for _, hits in got_hits("srand")] == [0]

    # Each puts() calls strlen() through an anonymous libc slot
    out = gdb.execute(r"track-got info -s .*libc -f \*ABS\*", to_string=True)
    assert max(int(n) for n in re.findall(r" (\d+) hits?", out)) >= 3, out

    gdb.execute("continue")
    assert [hits for _, hits in got_hits("puts")] == [3]
    assert [hits for _, hits in got_hits("srand")] == [2]

    # All three puts() calls come from the same call site in the loop
    [(puts_entry, _)] = got_hits("puts")
    out = gdb.execute(f"track-got query {puts_entry:#x}", to_string=True)
    assert "Tracking details for puts" in out
    assert "Called 3 times from stack:" in out
