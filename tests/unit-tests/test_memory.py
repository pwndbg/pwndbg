from __future__ import annotations

import sys
from unittest.mock import MagicMock

# Replace `pwndbg.commands` module with a mock to prevent import errors, as well
# as the `load_commands` function
module_name = "pwndbg.commands"
module = MagicMock(__name__=module_name, load_commands=lambda: None)
sys.modules[module_name] = module

# Load the mocks for the `gdb` and `gdblib` modules
import mocks.gdb
import mocks.gdblib  # noqa: F401

# We must import the function under test after all the mocks are imported
from pwndbg.lib.memory import round_down
from pwndbg.lib.memory import round_up


def test_basic_rounding():
    assert round_down(0xDEADBEEF, 0x1000) == 0xDEADB000
    assert round_up(0xDEADBEEF, 0x1000) == 0xDEADC000


def test_many_rounding():
    for n in range(0x100):
        for i in range(8):
            alignment = 1 << i
            down = round_down(n, alignment)
            up = round_up(n, alignment)
            assert down <= n and down + alignment > n and down % alignment == 0
            assert up >= n and up - alignment < n and up % alignment == 0
