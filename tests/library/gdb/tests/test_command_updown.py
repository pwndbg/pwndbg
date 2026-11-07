from __future__ import annotations

import gdb

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def test_up_updates_list_location_and_restores_frame_info(start_binary):
    start_binary(REFERENCE_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    frame_info_before = gdb.parameter("print frame-info")

    gdb.execute("up", to_string=True)
    assert gdb.selected_frame().name() == "main"

    # `list` must be centered on the caller's line (the `break_here();` call in main),
    # not on `break_here` itself (see #632).
    assert "8\t    break_here();" in gdb.execute("list", to_string=True)

    # `up` temporarily changes `print frame-info` and must put it back (see #4186).
    assert gdb.parameter("print frame-info") == frame_info_before


def test_down_restores_frame_info(start_binary):
    start_binary(REFERENCE_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    gdb.execute("set print frame-info source-and-location")
    gdb.execute("up", to_string=True)
    gdb.execute("down", to_string=True)

    assert gdb.selected_frame().name() == "break_here"
    assert gdb.parameter("print frame-info") == "source-and-location"
