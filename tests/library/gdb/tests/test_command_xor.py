from __future__ import annotations

import gdb

import pwndbg.aglib
import pwndbg.aglib.memory

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def test_command_xor_with_gdb_execute(start_binary):
    """
    Tests simple xoring
    """
    start_binary(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.sp
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    gdb.execute('xor $rsp " " 4')
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"AAAAaaaa"
