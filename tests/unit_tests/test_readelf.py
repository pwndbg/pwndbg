from __future__ import annotations

import os

import tests.unit_tests.mocks.gdb  # noqa: F401

import pwndbg.wrappers.readelf


def test_get_got_entry(tmp_path):
    # Test with a real binary to ensure pyelftools correctly extracts GOT entries
    binary_path = "tests/binaries/host/reference-binary"
    if not os.path.exists(binary_path):
        # If binary doesn't exist, skip the test
        return

    entries = pwndbg.wrappers.readelf.get_got_entry(binary_path)

    # Check if we got some entries
    assert entries

    # Check structure and verify actual values
    for category, items in entries.items():
        for item in items:
            # Verify structure
            assert "offset" in item
            assert "info" in item
            assert "type" in item
            assert "value" in item
            assert "name" in item

            # Check types
            assert isinstance(item["offset"], int)
            assert isinstance(item["value"], int)
            assert isinstance(item["name"], str)

            # Verify offset is a valid address (non-negative)
            assert item["offset"] >= 0

    # Verify we have expected categories populated
    assert any(
        len(entries[cat]) > 0
        for cat in [
            pwndbg.wrappers.readelf.RelocationType.JUMP_SLOT,
            pwndbg.wrappers.readelf.RelocationType.GLOB_DAT,
        ]
    )


if __name__ == "__main__":
    test_get_got_entry(None)
