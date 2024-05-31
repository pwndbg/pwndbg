from __future__ import annotations

import sys
from unittest.mock import MagicMock

# Replace `pwndbg.commands` module with a mock to prevent import errors, as well
# as the `load_commands` function
module_name = "pwndbg.commands"
module = MagicMock(__name__=module_name, load_commands=lambda: None)
sys.modules[module_name] = module

import os
import tempfile

# Load the mocks for the `gdb` and `gdblib` modules
import mocks.gdb
import mocks.gdblib  # noqa: F401

# We must import the function under test after all the mocks are imported
from pwndbg.lib.which import which


def test_basic():
    assert which("ls").endswith("/ls")


def test_nonexistent():
    assert which("definitely-not-a-real-command") is None


def test_dir():
    with tempfile.TemporaryDirectory() as tempdir:
        path = os.path.join(tempdir, "test_file")
        with open(path, "w") as f:
            f.write("test")
        os.chmod(path, 0o755)

        assert which(path) == path
