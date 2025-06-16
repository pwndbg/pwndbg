from __future__ import annotations

import sys


def test_readline_import_error():
    """
    Importing CPython readline breaks GDB's use of GNU readline.
    This breaks GDB tab autocomplete.

    It's easy to accidentally import something that imports readline far down
    the dependency chain. This test ensures we don't ever do that.

    For more info see https://github.com/pwndbg/pwndbg/issues/2232
    """
    try:
        import readline  # noqa: F401
    except ImportError:
        pass
    assert "readline" not in sys.modules
