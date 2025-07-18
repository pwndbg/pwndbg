from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest
from pwnlib.util.packing import p64

# Replace `pwndbg.commands` module with a mock to prevent import errors, as well
# as the `load_commands` function
module_name = "pwndbg.commands"
module = MagicMock(__name__=module_name, load_commands=lambda: None)
sys.modules[module_name] = module

# Load the mock for the `pwndbg.dbg` object and `aglib` module.
import mocks.aglib
import mocks.dbg

# Load the mocks for the `gdb` and `gdblib` modules
import mocks.gdb
import mocks.gdblib  # noqa: F401

# We must import the function under test after all the mocks are imported
from pwndbg.lib.heap.helpers import find_fastbin_size


def setup_mem(max_size, offsets):
    buf = bytearray([0] * max_size)
    for offset, value in offsets.items():
        buf[offset : offset + 8] = p64(value)

    return buf


def test_too_small():
    max_size = 0x80
    offsets = {
        0x8: 0x10,
    }
    buf = setup_mem(max_size, offsets)
    with pytest.raises(StopIteration):
        next(find_fastbin_size(buf, max_size, 1))

    with pytest.raises(StopIteration):
        next(find_fastbin_size(buf, max_size, 8))


def test_normal():
    max_size = 0x20
    offsets = {
        0x8: 0x20,
    }
    buf = setup_mem(max_size, offsets)
    assert 0x0 == next(find_fastbin_size(buf, max_size, 1))
    assert 0x0 == next(find_fastbin_size(buf, max_size, 8))


def test_nozero_flags():
    max_size = 0x20
    offsets = {
        0x8: 0x2F,
    }
    buf = setup_mem(max_size, offsets)
    assert 0x0 == next(find_fastbin_size(buf, max_size, 1))
    assert 0x0 == next(find_fastbin_size(buf, max_size, 8))


def test_unaligned():
    max_size = 0x20
    offsets = {
        0x9: 0x20,
    }
    buf = setup_mem(max_size, offsets)
    assert 0x1 == next(find_fastbin_size(buf, max_size, 1))
    with pytest.raises(StopIteration):
        next(find_fastbin_size(buf, max_size, 8))
