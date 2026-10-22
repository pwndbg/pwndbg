from __future__ import annotations

import re

import gdb

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


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
