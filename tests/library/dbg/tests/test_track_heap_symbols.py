from __future__ import annotations

import re
from collections.abc import Callable

import gdb

from .. import get_binary

REFERENCE_BINARY = get_binary("heap_tracker_symbols.native.out")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def test_track_heap_symbols_annotates_caller(start_binary: Callable[..., None]) -> None:
    """`track-heap enable --where` annotates malloc, realloc, and free with the calling symbol (#3092)."""
    start_binary(REFERENCE_BINARY)
    gdb.execute("entry")

    gdb.execute("track-heap enable --where")
    output = _ANSI.sub("", gdb.execute("continue", to_string=True))

    assert "@ do_alloc" in output
    assert "@ do_realloc" in output
    assert "@ main" in output


def test_track_heap_without_symbols_is_unchanged(start_binary: Callable[..., None]) -> None:
    """Default output must not carry the `@` annotation."""
    start_binary(REFERENCE_BINARY)
    gdb.execute("entry")

    gdb.execute("track-heap enable")
    output = gdb.execute("continue", to_string=True)

    assert "@" not in output
