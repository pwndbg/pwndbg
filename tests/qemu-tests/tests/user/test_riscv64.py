from __future__ import annotations

import sys
import traceback

import gdb

import pwndbg

try:
    gdb.execute("break 4")
    assert pwndbg.gdblib.symbol.address("main") == 0x4000000668
    gdb.execute("continue")

    gdb.execute("stepuntilasm jalr")

    # verify call argument are enriched
    assembly = gdb.execute("nearpc", to_string=True)
    assert "'Not enough args'" in assembly

except AssertionError:
    traceback.print_exc(file=sys.stdout)
    sys.exit(1)
