from __future__ import annotations

import sys

import mocks.gdb  # noqa: F401
import mocks.gdblib  # noqa: F401

import pwndbg  # noqa: F401


def test_readline_not_imported():
    """
    Importing CPython readline breaks GDB's use of GNU readline.
    This breaks GDB tab autocomplete.

    It's easy to accidentally import something that imports readline far down
    the dependency chain. This test ensures we don't ever do that.

    For more info see https://github.com/pwndbg/pwndbg/issues/2232
    """
    assert "readline" not in sys.modules
