from __future__ import annotations

import os

import pytest

BINARY_PATH = "tests/binaries/host/reference-binary.native.out"


@pytest.mark.skipif(not os.path.exists(BINARY_PATH), reason="test binary not built")
def test_get_got_entry() -> None:
    import pwndbg.lib.got

    entries = pwndbg.lib.got.get_got_entry(BINARY_PATH)

    # Check structure
    assert entries

    # Verify structure and types
    for category, items in entries.items():
        for item in items:
            assert isinstance(item["offset"], int)
            assert isinstance(item["value"], int)
            assert isinstance(item["name"], str)
            assert item["offset"] >= 0

    # Check for specific expected symbols
    all_names = [str(item["name"]) for items in entries.values() for item in items]

    assert any("puts" in name for name in all_names), "Expected 'puts' symbol"
    assert any("libc_start_main" in name for name in all_names), (
        "Expected '__libc_start_main' symbol"
    )

    # Verify symbol versions are included
    versioned_symbols = [name for name in all_names if "@GLIBC" in name]
    assert len(versioned_symbols) > 0, "Expected at least one symbol with GLIBC version"
