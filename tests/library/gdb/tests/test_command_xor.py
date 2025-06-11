from __future__ import annotations

import gdb

import pwndbg.aglib.memory
import pwndbg.aglib.regs
import tests
from pwndbg.commands.xor import memfrob

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_xor_with_gdb_execute(start_binary):
    """
    Tests simple xoring
    """
    start_binary(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    gdb.execute("xor $rsp ' ' 4")
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"AAAAaaaa"


def test_command_xor_with_int(start_binary):
    """
    Tests simple xoring
    """
    start_binary(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    assert isinstance(before, int)
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    gdb.execute(f"xor {before} ' ' 4")
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"AAAAaaaa"


def test_command_xor_with_hex(start_binary):
    """
    Tests simple xoring
    """
    start_binary(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    before_hex = hex(before)
    assert isinstance(before_hex, str)
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    gdb.execute(f"xor {before_hex} ' ' 4")
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"AAAAaaaa"


def test_command_memfrob(start_binary):
    start_binary(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    memfrob(before, 4)
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"KKKKaaaa"
