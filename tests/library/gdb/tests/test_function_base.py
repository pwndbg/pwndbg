from __future__ import annotations

import gdb

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.out")


def test_function_base(start_binary):
    start_binary(REFERENCE_BINARY)

    result = gdb.execute('p/x $base("reference-binary")', to_string=True).strip()

    assert result.startswith("$1 = 0x") and result.endswith("000")
