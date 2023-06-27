import re
import sys
import traceback

import gdb

import pwndbg

try:
    gdb.execute("set disable-color on")

    gdb.execute("break 4")
    assert pwndbg.gdblib.symbol.address("main") == 0x4000000668
    gdb.execute("continue")

    gdb.execute("nextcall", to_string=True)

    # verify call argument are enriched
    assembly = gdb.execute("nearpc", to_string=True)
    assert re.search(r"s.*'Not enough args'", assembly), assembly
except AssertionError:
    traceback.print_exc()
    sys.exit(1)
