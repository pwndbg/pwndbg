from __future__ import annotations

from typing import Any

import gdb

from . import get_binary

REFERENCE_BINARY = get_binary("heap_bins.native.out")


def test_function_heap(start_binary: Any) -> None:

    start_binary(REFERENCE_BINARY)

    # Force heuristics since libc symbols are missing in test environment
    gdb.execute("set resolve-heap-via-heuristic force", to_string=True)

    # Break on breakpoint() to ensure malloc has run and heap is initialized
    gdb.execute("break breakpoint", to_string=True)
    gdb.execute("continue", to_string=True)

    # Verify the $heap() function
    result = gdb.execute("p/x $heap()", to_string=True).strip()
    assert result.startswith("$1 = 0x")

    # Verify $heap(offset)
    result_offset = gdb.execute("p/x $heap(0x20)", to_string=True).strip()
    assert result_offset.startswith("$2 = 0x")

    # Verify offset math
    addr1 = int(result.split(" = ")[1], 16)
    addr2 = int(result_offset.split(" = ")[1], 16)
    assert addr2 - addr1 == 0x20
