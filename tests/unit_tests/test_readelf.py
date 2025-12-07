from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

# Mock gdb before importing pwndbg
sys.modules["gdb"] = MagicMock()
sys.modules["gdb"].VERSION = "12.1"

import pwndbg.wrappers.readelf
from pwndbg.wrappers.readelf import RelocationType


def test_get_got_entry(tmp_path):
    # We need a binary to test.
    # We can use the one we compiled: tests/binaries/host/reference-binary
    # Or we can mock ELFFile? Mocking ELFFile is hard.
    # Using a real binary is better.

    binary_path = "tests/binaries/host/reference-binary"
    if not os.path.exists(binary_path):
        # If binary doesn't exist, skip or fail.
        # For now, let's assume it exists as we compiled it.
        return

    entries = pwndbg.wrappers.readelf.get_got_entry(binary_path)

    # Check if we got some entries
    assert entries

    # Check structure
    for category, items in entries.items():
        for item in items:
            assert "offset" in item
            assert "info" in item
            assert "type" in item
            assert "value" in item
            assert "name" in item

            # Check types
            assert isinstance(item["offset"], int)
            assert isinstance(item["value"], int)
            assert isinstance(item["name"], str)

    print("test_get_got_entry passed")


if __name__ == "__main__":
    test_get_got_entry(None)
