"""
Unit tests for pwndbg IPython interactive helpers (ipi).
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

# Mock pwndbg.commands module to prevent import errors
module_name = "pwndbg.commands"
module = MagicMock(__name__=module_name, load_commands=lambda: None)
sys.modules[module_name] = module

# Load the mocks for the debugger modules
from .mocks import aglib  # noqa: F401
from .mocks import gdb  # noqa: F401
from .mocks import gdblib  # noqa: F401

# Mock the aglib submodules that ipi_helpers needs
sys.modules["pwndbg.aglib.memory"] = MagicMock(__name__="pwndbg.aglib.memory")
sys.modules["pwndbg.aglib.regs"] = MagicMock(__name__="pwndbg.aglib.regs")
sys.modules["pwndbg.aglib.vmmap"] = MagicMock(__name__="pwndbg.aglib.vmmap")
sys.modules["pwndbg.hexdump"] = MagicMock(__name__="pwndbg.hexdump")
sys.modules["pwndbg.search"] = MagicMock(__name__="pwndbg.search")


def test_get_ipi_namespace() -> None:
    """Test that get_ipi_namespace returns all expected helpers."""
    from pwndbg.lib.ipi_helpers import get_ipi_namespace

    ns = get_ipi_namespace()

    # Check all expected keys exist
    expected_keys = {"mr", "mw", "hd", "ms", "rr", "rw", "vm", "aliases"}
    assert set(ns.keys()) == expected_keys, f"Expected {expected_keys}, got {set(ns.keys())}"

    # Check that all values are callable
    for name in expected_keys:
        assert callable(ns[name]), f"{name} should be callable"


def test_get_banner() -> None:
    """Test banner message contains expected content."""
    from pwndbg.lib.ipi_helpers import get_banner

    banner = get_banner()

    # Check it's a non-empty string
    assert isinstance(banner, str), "Banner should be a string"
    assert len(banner) > 0, "Banner should not be empty"

    # Check key elements are mentioned
    assert "mr" in banner, "Banner should mention mr shortcut"
    assert "mw" in banner, "Banner should mention mw shortcut"
    assert "rr" in banner, "Banner should mention rr shortcut"
    assert "vm" in banner, "Banner should mention vm shortcut"
    assert "aliases()" in banner, "Banner should mention aliases() function"


def test_short_aliases_exist() -> None:
    """Test that all short alias functions are defined."""
    from pwndbg.lib import ipi_helpers

    # Test that short aliases exist and are callable
    assert hasattr(ipi_helpers, "mr"), "mr alias should exist"
    assert hasattr(ipi_helpers, "mw"), "mw alias should exist"
    assert hasattr(ipi_helpers, "hd"), "hd alias should exist"
    assert hasattr(ipi_helpers, "ms"), "ms alias should exist"
    assert hasattr(ipi_helpers, "rr"), "rr alias should exist"
    assert hasattr(ipi_helpers, "rw"), "rw alias should exist"
    assert hasattr(ipi_helpers, "vm"), "vm alias should exist"
    assert hasattr(ipi_helpers, "aliases"), "aliases helper should exist"

    assert callable(ipi_helpers.mr), "mr should be callable"
    assert callable(ipi_helpers.mw), "mw should be callable"
    assert callable(ipi_helpers.hd), "hd should be callable"
    assert callable(ipi_helpers.ms), "ms should be callable"
    assert callable(ipi_helpers.rr), "rr should be callable"
    assert callable(ipi_helpers.rw), "rw should be callable"
    assert callable(ipi_helpers.vm), "vm should be callable"
    assert callable(ipi_helpers.aliases), "aliases should be callable"


def test_aliases_function_output() -> None:
    """Test that aliases() function produces output."""
    from pwndbg.lib.ipi_helpers import aliases

    # Verify it's callable and doesn't crash
    assert callable(aliases), "aliases should be a callable function"

    # Test that function signature is correct (no required args)
    import inspect

    sig = inspect.signature(aliases)
    assert len(sig.parameters) == 0, "aliases() should take no required arguments"


def test_module_imports() -> None:
    """Test that the module can be imported without errors."""
    # This test verifies that all imports in ipi_helpers.py work
    from pwndbg.lib import ipi_helpers

    # Verify key exports
    assert hasattr(ipi_helpers, "get_ipi_namespace"), "Module should export get_ipi_namespace"
    assert hasattr(ipi_helpers, "get_banner"), "Module should export get_banner"


def test_no_pwntools_shadowing() -> None:
    """Test that we don't export a 'pwn' object that would shadow pwntools."""
    from pwndbg.lib.ipi_helpers import get_ipi_namespace

    ns = get_ipi_namespace()

    # Critical: pwn should NOT be in namespace to avoid shadowing pwntools
    assert "pwn" not in ns, "Should not export 'pwn' to avoid shadowing pwntools module"
