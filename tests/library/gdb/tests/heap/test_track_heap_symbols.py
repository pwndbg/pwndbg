from __future__ import annotations

import gdb

from .. import get_binary

REFERENCE_BINARY = get_binary("heap_tracker_symbols.native.out")


def test_track_heap_symbols_annotates_caller(start_binary):
    """`track-heap enable --symbols` annotates malloc, realloc, and free with the calling symbol (#3092)."""
    start_binary(REFERENCE_BINARY)
    gdb.execute("entry")

    gdb.execute("track-heap enable --symbols")
    output = gdb.execute("continue", to_string=True)

    assert "<- do_alloc" in output
    assert "<- do_realloc" in output
    assert "<- main" in output


def test_track_heap_without_symbols_is_unchanged(start_binary):
    """Default output must not carry the `<-` annotation."""
    start_binary(REFERENCE_BINARY)
    gdb.execute("entry")

    gdb.execute("track-heap enable")
    output = gdb.execute("continue", to_string=True)

    assert "<-" not in output
