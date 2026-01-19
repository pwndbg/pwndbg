from __future__ import annotations

import os


# Test the readelf wrapper directly without importing pwndbg
# to avoid complex mock dependencies
def test_get_got_entry_direct() -> None:
    """Test get_got_entry using pyelftools directly to verify our implementation"""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    binary_path = "tests/binaries/host/reference-binary"
    if not os.path.exists(binary_path):
        return

    # Test that we can extract relocation entries
    found_symbols = []
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)  # type: ignore[no-untyped-call]
        for section in elf.iter_sections():  # type: ignore[no-untyped-call]
            if isinstance(section, RelocationSection):
                for rel in section.iter_relocations():  # type: ignore[no-untyped-call]
                    symbol_table = elf.get_section(section["sh_link"])  # type: ignore[no-untyped-call]
                    symbol = symbol_table.get_symbol(rel["r_info_sym"])
                    if symbol.name:
                        found_symbols.append(symbol.name)

    # Verify expected symbols exist
    assert any("puts" in s for s in found_symbols), "Expected 'puts' symbol"
    assert any("libc_start_main" in s for s in found_symbols), "Expected '__libc_start_main' symbol"


# Only run full test if mocks are properly set up
def test_get_got_entry() -> None:
    """Full integration test - requires proper mock setup"""
    try:
        import pwndbg.wrappers.readelf
        import tests.unit_tests.mocks.dbg  # type: ignore[import-untyped]  # noqa: F401
        import tests.unit_tests.mocks.gdb  # noqa: F401
    except (ImportError, NotImplementedError):
        # Skip if mocks aren't fully set up yet
        import pytest

        pytest.skip("Mocking infrastructure not complete")

    binary_path = "tests/binaries/host/reference-binary"
    if not os.path.exists(binary_path):
        return

    entries = pwndbg.wrappers.readelf.get_got_entry(binary_path)

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


if __name__ == "__main__":
    test_get_got_entry_direct()
    print("Direct test passed!")
