from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# Replace `pwndbg.commands` module with a mock to prevent import errors, as well
# as the `load_commands` function
module_name = "pwndbg.commands"
module = MagicMock(__name__=module_name, load_commands=lambda: None)
sys.modules[module_name] = module

# We must import the function under test after all the mocks are imported
from pwndbg.lib.memory import Page
from pwndbg.lib.memory import round_down
from pwndbg.lib.memory import round_up

# Load the mocks for the `gdb` and `gdblib` modules
from .mocks import gdb  # noqa: F401
from .mocks import gdblib  # noqa: F401


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


@pytest.mark.parametrize(
    "objfile, expected",
    [
        ("/usr/lib/libc.so.6", True),
        ("/tmp/a b", True),
        ("", False),
        ("[stack]", False),
        ("[anon_shmem:name]", False),
        ("anon_inode:[perf_event]", False),
        ("<qemu>", False),
        ("<explored_12345>", False),
        ("/dev/zero (deleted)", False),
        ("/SYSV00000000 (deleted)", False),
        ("/memfd:name (deleted)", False),
        ("/tmp/a.out (deleted)", False),
    ],
)
def test_is_memory_mapped_file(objfile, expected):
    assert Page(0x1000, 0x1000, 4, 0, 8, objfile).is_memory_mapped_file == expected
