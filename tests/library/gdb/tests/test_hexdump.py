from __future__ import annotations

import gdb

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.memory

from . import get_binary

BINARY = get_binary("reference-binary.native.out")

# NOTE: Not the same as the dbg/ test!!!


def test_hexdump_code_py_format(start_binary):
    start_binary(BINARY)
    sp = pwndbg.aglib.regs.sp
    assert sp is not None

    pwndbg.aglib.memory.write(sp, b"abcdefgh\x01\x02\x03\x04\x05\x06\x07\x08" * 16)

    SIZE = 21
    out = gdb.execute(f"hexdump -C py $rsp {SIZE}", to_string=True)

    expected = (
        "data = (\n"
        '    b"\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08"\n'
        '    b"\\x61\\x62\\x63\\x64\\x65"\n'
        ")\n"
    )
    assert out.rstrip("\n") == expected.rstrip("\n")


def test_hexdump_code_c_format(start_binary):
    start_binary(BINARY)
    sp = pwndbg.aglib.regs.sp
    assert sp is not None

    pwndbg.aglib.memory.write(sp, b"abcdefgh\x01\x02\x03\x04\x05\x06\x07\x08" * 16)

    SIZE = 21
    out = gdb.execute(f"hexdump -C c $rsp {SIZE}", to_string=True)

    expected = (
        "static const unsigned char data[] = {\n"
        "    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,\n"
        "    0x61, 0x62, 0x63, 0x64, 0x65,\n"
        "};\n"
    )
    assert out.rstrip("\n") == expected.rstrip("\n")
