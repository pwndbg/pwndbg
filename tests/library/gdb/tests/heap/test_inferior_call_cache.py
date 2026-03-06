"""Regression test for https://github.com/pwndbg/pwndbg/issues/1563

Calling inferior functions (e.g. ``malloc``) from Python via
``gdb.execute('call ...')`` does not fire ``gdb.events.stop``, so caches
keyed on "stop" — most importantly vmmap — used to become stale.  After
enough ``malloc`` calls the heap would grow via ``brk``, and pwndbg's
cached memory map would no longer cover the new region, causing
``thread_arena`` / ``heap`` to crash with "Cannot build heap object on
an unmapped address".

The fix hooks ``gdb.events.inferior_call`` to clear stop-caches after
each inferior function call completes.
"""

from __future__ import annotations

import gdb

import pwndbg.aglib.heap
from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

from .. import get_binary

REFERENCE_BINARY = get_binary("reference_bin_pie.native.out")


def test_heap_after_many_inferior_mallocs(start_binary):
    """thread_arena must remain accessible after many inferior malloc calls.

    Reproducer from issue #1563: repeatedly call malloc from Python and
    read ``thread_arena`` between calls.  Without the inferior_call cache
    fix this crashes after the heap outgrows the cached vmmap.
    """
    start_binary(REFERENCE_BINARY)
    gdb.execute("entry")

    allocator = pwndbg.aglib.heap.current
    assert isinstance(allocator, GlibcMemoryAllocator)

    # Use a large size (0x10000) to force brk expansion quickly.
    print("Will print next thread arenas, their sizes should increase gradually")
    for _ in range(10):
        gdb.execute("call (void *)malloc(0x10000)", to_string=True)
        print(pwndbg.aglib.heap.current.thread_arena)  # type: ignore[union-attr]
