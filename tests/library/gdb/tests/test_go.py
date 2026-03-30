from __future__ import annotations

import gdb

from . import get_binary

GOSAMPLE_X64 = get_binary("gosample.x86-64.out")
GOSAMPLE_X86 = get_binary("gosample.i386.out")

# NOTE: Not the same as the dbg/ test!!!


def test_typeinfo_go_x64():
    """
    Tests pwndbg's typeinfo knows about the Go x64 types.
    Catches: Python Exception <class 'gdb.error'> No type named u8.:
    Test catches the issue only if the binaries are not stripped.
    """
    gdb.execute("file " + GOSAMPLE_X64)
    start = gdb.execute("start", to_string=True)
    assert "Python Exception" not in start


def test_typeinfo_go_x86():
    """
    Tests pwndbg's typeinfo knows about the Go x32 types
    Catches: Python Exception <class 'gdb.error'> No type named u8.:
    Test catches the issue only if the binaries are not stripped.
    """
    gdb.execute("file " + GOSAMPLE_X86)
    start = gdb.execute("start", to_string=True)
    assert "Python Exception" not in start
