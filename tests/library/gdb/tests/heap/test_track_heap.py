"""Tests for the heap tracker report printer (``track-heap enable``).

See https://github.com/pwndbg/pwndbg/issues/3090: each pointer in the report is
colorized so a malloc/realloc can be visually matched with its later free. The
tracker is GDB-only (it relies on ``gdb.FinishBreakpoint`` and watchpoints), so
these tests live in the GDB-specific suite.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import gdb

from .. import get_binary

REFERENCE_BINARY = get_binary("heap_tracker.native.out")

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip(text: str) -> str:
    return ANSI.sub("", text)


def _color_of(line: str, addr: str) -> str | None:
    """Return the ANSI escape immediately preceding ``addr`` in ``line``."""
    match = re.search(r"(\x1b\[[0-9;]*m)" + re.escape(addr), line)
    return match.group(1) if match else None


def _run_tracker(start_binary: Callable[..., None]) -> str:
    """Enable the tracker at ``break_here`` and return the report output."""
    start_binary(REFERENCE_BINARY)

    gdb.execute("break break_here")
    gdb.execute("continue", to_string=True)

    gdb.execute("track-heap enable", to_string=True)
    return gdb.execute("continue", to_string=True)


def test_track_heap_colorizes_realloc_pointer(start_binary: Callable[..., None]) -> None:
    """A realloc()'d pointer is colorized and matches the color of its free()."""
    # Colors are disabled by default during tests (NO_COLOR=1); turn them on.
    gdb.execute("set disable-colors off")

    output = _run_tracker(start_binary)
    lines = output.splitlines()

    realloc_lines = [line for line in lines if "[*] realloc(" in line and "->" in line]
    assert realloc_lines, f"no realloc report line found in:\n{output}"
    realloc_line = realloc_lines[0]

    ret_match = re.search(r"->\s*(0x[0-9a-f]+)", _strip(realloc_line))
    assert ret_match is not None, f"could not parse realloc return pointer: {realloc_line!r}"
    ret_addr = ret_match.group(1)

    # The returned pointer must be colorized in the realloc report line.
    ret_color = _color_of(realloc_line, ret_addr)
    assert ret_color is not None, f"realloc return pointer not colorized: {realloc_line!r}"

    # The later free() of that same pointer must use the same color, so the
    # allocation can be visually matched with its free.
    free_lines = [line for line in lines if "free(" in line and ret_addr in _strip(line)]
    assert free_lines, f"no free() line for {ret_addr} in:\n{output}"
    assert _color_of(free_lines[0], ret_addr) == ret_color


def test_track_heap_realloc_zero_size(start_binary: Callable[..., None]) -> None:
    """realloc(ptr, 0) is handled gracefully without raising or asserting."""
    output = _run_tracker(start_binary)

    # It is implementation-defined, so the tracker only warns and carries on.
    assert "implementation defined" in output
    # Regression guards for the previously-broken realloc(ptr, 0) path.
    assert "AttributeError" not in output
    assert "Traceback" not in output
    assert "re-entrant" not in output
