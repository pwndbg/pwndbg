import gdb

import pwndbg.memory
import pwndbg.regs
import tests
from pwndbg.commands.xor import memfrob
from pwndbg.commands.xor import xor

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_xor_with_gdb_execute(start_binary):
    """
    Tests simple xoring
    """
    start_binary(REFERENCE_BINARY)

    before = pwndbg.regs.rsp
    pwndbg.memory.write(before, b"aaaaaaaa")
    gdb.execute("xor $rsp ' ' 4")
    after = pwndbg.memory.read(before, 8)
    assert after == b"AAAAaaaa"


def test_command_xor_with_int(start_binary):
    """
    Tests simple xoring
    """
    start_binary(REFERENCE_BINARY)

    before = pwndbg.regs.rsp
    assert isinstance(before, int)
    pwndbg.memory.write(before, b"aaaaaaaa")
    gdb.execute(f"xor {before} ' ' 4")
    after = pwndbg.memory.read(before, 8)
    assert after == b"AAAAaaaa"


def test_command_xor_with_hex(start_binary):
    """
    Tests simple xoring
    """
    start_binary(REFERENCE_BINARY)

    before = pwndbg.regs.rsp
    before_hex = hex(before)
    assert isinstance(before_hex, str)
    pwndbg.memory.write(before, b"aaaaaaaa")
    gdb.execute(f"xor {before_hex} ' ' 4")
    after = pwndbg.memory.read(before, 8)
    assert after == b"AAAAaaaa"


def test_command_memfrob(start_binary):
    start_binary(REFERENCE_BINARY)

    before = pwndbg.regs.rsp
    pwndbg.memory.write(before, b"aaaaaaaa")
    memfrob(before, 4)
    after = pwndbg.memory.read(before, 8)
    assert after == b"KKKKaaaa"
