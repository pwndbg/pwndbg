from __future__ import annotations

import gdb

import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import tests

MEMORY_BINARY = tests.binaries.get("memory.out")
X86_BINARY = tests.binaries.get("gosample.x86")

data_addr = "0x400081"


def test_windbg_dX_commands(start_binary):
    """
    Tests windbg compatibility commands that dump memory
    like dq, dw, db, ds etc.
    """
    start_binary(MEMORY_BINARY)

    # Try to fail commands in different way
    for cmd_prefix in ("dq", "dd", "dw", "db"):
        # With a non-existent symbol
        cmd = cmd_prefix + " nonexistentsymbol"
        assert gdb.execute(cmd, to_string=True) == (
            "usage: XX [-h] address [count]\n"
            "XX: error: argument address: Incorrect address (or GDB expression): nonexistentsymbol\n"
        ).replace("XX", cmd_prefix)

        # With an invalid/unmapped address
        cmd = cmd_prefix + " 0"
        assert gdb.execute(cmd, to_string=True) == "Could not access the provided address\n"

    #################################################
    #### dq command tests
    #################################################
    # Try `dq` with symbol, &symbol, 0x<address> and <address> without 0x prefix (treated as hex!)
    dq1 = gdb.execute("dq data", to_string=True)
    dq2 = gdb.execute("dq &data", to_string=True)
    dq3 = gdb.execute(f"dq {data_addr}", to_string=True)
    dq4 = gdb.execute(f"dq {data_addr.replace('0x', '')}", to_string=True)
    assert (
        dq1
        == dq2
        == dq3
        == dq4
        == (
            "0000000000400081     0000000000000000 0000000000000001\n"
            "0000000000400091     0000000100000002 0001000200030004\n"
            "00000000004000a1     0102030405060708 1122334455667788\n"
            "00000000004000b1     0123456789abcdef 0000000000000000\n"
        )
    )

    # Try `dq` with different counts
    dq_count1 = gdb.execute("dq data 2", to_string=True)
    dq_count2 = gdb.execute("dq &data 2", to_string=True)
    dq_count3 = gdb.execute(f"dq {data_addr} 2", to_string=True)
    assert (
        dq_count1
        == dq_count2
        == dq_count3
        == "0000000000400081     0000000000000000 0000000000000001\n"
    )

    assert gdb.execute("dq data 1", to_string=True) == "0000000000400081     0000000000000000\n"
    assert gdb.execute("dq data 3", to_string=True) == (
        "0000000000400081     0000000000000000 0000000000000001\n"
        "0000000000400091     0000000100000002\n"
    )

    # Try 'dq' with count equal to a register, but lets set it before ;)
    # also note that we use `data2` here
    assert gdb.execute("set $eax=4", to_string=True) == ""  # assert as a sanity check
    assert gdb.execute("dq data2 $eax", to_string=True) == (
        "00000000004000a9     1122334455667788 0123456789abcdef\n"
        "00000000004000b9     0000000000000000 ffffffffffffffff\n"
    )

    # See if we can repeat dq command (use count for shorter data)
    assert gdb.execute("dq data2 2", to_string=True) == (
        "00000000004000a9     1122334455667788 0123456789abcdef\n"
    )

    # TODO/FIXME: Can we test command repeating here? Neither passing `from_tty=True`
    # or setting `pwndbg.commands.windbg.dq.repeat = True` works here
    # assert gdb.execute('dq data2 2', to_string=True, from_tty=True) == (
    #    '00000000004000b9     0000000000000000 ffffffffffffffff\n'
    # )

    #################################################
    #### dd command tests
    #################################################
    dd1 = gdb.execute("dd data", to_string=True)
    dd2 = gdb.execute("dd &data", to_string=True)
    dd3 = gdb.execute(f"dd {data_addr}", to_string=True)
    dd4 = gdb.execute(f"dd {data_addr.replace('0x', '')}", to_string=True)
    assert (
        dd1
        == dd2
        == dd3
        == dd4
        == (
            "0000000000400081     00000000 00000000 00000001 00000000\n"
            "0000000000400091     00000002 00000001 00030004 00010002\n"
            "00000000004000a1     05060708 01020304 55667788 11223344\n"
            "00000000004000b1     89abcdef 01234567 00000000 00000000\n"
        )
    )

    # count tests
    assert gdb.execute("dd data 4", to_string=True) == (
        "0000000000400081     00000000 00000000 00000001 00000000\n"
    )
    assert gdb.execute("dd data 3", to_string=True) == (
        "0000000000400081     00000000 00000000 00000001\n"
    )

    #################################################
    #### dw command tests
    #################################################
    dw1 = gdb.execute("dw data", to_string=True)
    dw2 = gdb.execute("dw &data", to_string=True)
    dw3 = gdb.execute(f"dw {data_addr}", to_string=True)
    dw4 = gdb.execute(f"dw {data_addr.replace('0x', '')}", to_string=True)
    assert (
        dw1
        == dw2
        == dw3
        == dw4
        == (
            "0000000000400081     0000 0000 0000 0000 0001 0000 0000 0000\n"
            "0000000000400091     0002 0000 0001 0000 0004 0003 0002 0001\n"
            "00000000004000a1     0708 0506 0304 0102 7788 5566 3344 1122\n"
            "00000000004000b1     cdef 89ab 4567 0123 0000 0000 0000 0000\n"
        )
    )

    # count tests
    assert gdb.execute("dw data 8", to_string=True) == (
        "0000000000400081     0000 0000 0000 0000 0001 0000 0000 0000\n"
    )

    assert gdb.execute("dw data 8/2", to_string=True) == (
        "0000000000400081     0000 0000 0000 0000\n"
    )

    assert gdb.execute("dw data $eax", to_string=True) == (
        "0000000000400081     0000 0000 0000 0000\n"
    )

    #################################################
    #### db command tests
    #################################################
    db1 = gdb.execute("db data", to_string=True)
    db2 = gdb.execute("db &data", to_string=True)
    db3 = gdb.execute(f"db {data_addr}", to_string=True)
    db4 = gdb.execute(f"db {data_addr.replace('0x', '')}", to_string=True)
    assert (
        db1
        == db2
        == db3
        == db4
        == (
            "0000000000400081     00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00\n"
            "0000000000400091     02 00 00 00 01 00 00 00 04 00 03 00 02 00 01 00\n"
            "00000000004000a1     08 07 06 05 04 03 02 01 88 77 66 55 44 33 22 11\n"
            "00000000004000b1     ef cd ab 89 67 45 23 01 00 00 00 00 00 00 00 00\n"
        )
    )

    # count tests
    assert gdb.execute("db data 31", to_string=True) == (
        "0000000000400081     00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00\n"
        "0000000000400091     02 00 00 00 01 00 00 00 04 00 03 00 02 00 01\n"
    )
    assert gdb.execute("db data $ax", to_string=True) == ("0000000000400081     00 00 00 00\n")

    #################################################
    #### dc command tests
    #################################################
    dc1 = gdb.execute("dc data", to_string=True)
    dc2 = gdb.execute("dc &data", to_string=True)
    dc3 = gdb.execute(f"dc {data_addr}", to_string=True)
    dc4 = gdb.execute(f"dc {data_addr.replace('0x', '')}", to_string=True)
    assert (
        dc1
        == dc2
        == dc3
        == dc4
        == (
            "+0000 0x400081  00 00 00 00 00 00 00 00                           "
            "│........│        │\n"
        )
    )

    assert gdb.execute("dc data 3", to_string=True) == (
        "+0000 0x400081  00 00 00                                          │...     │        │\n"
    )

    #################################################
    #### ds command tests
    #################################################
    ds1 = gdb.execute("ds short_str", to_string=True)
    ds2 = gdb.execute("ds &short_str", to_string=True)
    ds3 = gdb.execute("ds 0x4000d9", to_string=True)
    ds4 = gdb.execute("ds 4000d9", to_string=True)
    assert ds1 == ds2 == ds3 == ds4 == "4000d9 'some cstring here'\n"

    # Check too low maxlen
    assert gdb.execute("ds short_str 5", to_string=True) == (
        "Max str len of 5 too low, changing to 256\n4000d9 'some cstring here'\n"
    )

    # Check output for a string longer than (the default) maxlen of 256
    assert gdb.execute("ds long_str", to_string=True) == (
        "4000eb 'long string: "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...'\n"
    )

    # Check impossible address
    assert gdb.execute("ds 0", to_string=True) == (
        "Data at address can't be dereferenced or is not a printable null-terminated "
        "string or is too short.\n"
        "Perhaps try: db <address> <count> or hexdump <address>\n"
    )


def test_windbg_eX_commands(start_binary):
    """
    Tests windbg compatibility commands that write to memory
    like eq, ed, ew, eb etc.
    """
    start_binary(MEMORY_BINARY)

    # Try to fail commands in different way
    for cmd_prefix in ("eq", "ed", "ew", "eb"):
        # With a non-existent symbol
        cmd = cmd_prefix + " nonexistentsymbol"

        # Seems there is some mismatch between Python 3.x argparse output
        expected_in = (
            # This version occurred locally when tested on Python 3.9.5
            (
                "usage: XX [-h] address [data ...]\n"
                "XX: error: argument address: Incorrect address (or GDB expression): nonexistentsymbol\n"
            ).replace("XX", cmd_prefix),
            # This version occurs on CI on Python 3.8.10
            (
                "usage: XX [-h] address [data [data ...]]\n"
                "XX: error: argument address: Incorrect address (or GDB expression): nonexistentsymbol\n"
            ).replace("XX", cmd_prefix),
        )

        assert gdb.execute(cmd, to_string=True) in expected_in
        assert gdb.execute(cmd, to_string=True) in expected_in

        # With no data arguments provided
        cmd = cmd_prefix + " 0"
        assert gdb.execute(cmd, to_string=True) == "Cannot write empty data into memory.\n"

        # With invalid/unmapped address 0
        cmd = cmd_prefix + " 0 1122"
        assert gdb.execute(cmd, to_string=True) == ("Cannot access memory at address 0x0\n")

        # With invalid data which can't be parsed as hex
        cmd = cmd_prefix + " 0 x"
        assert gdb.execute(cmd, to_string=True) == (
            "Incorrect data format: it must all be a hex value (0x1234 or 1234, both "
            "interpreted as 0x1234)\n"
        )
    #########################################
    ### Test eq write
    #########################################
    assert gdb.execute("eq $sp 0xcafebabe", to_string=True) == ""
    assert "0x00000000cafebabe" in gdb.execute("x/xg $sp", to_string=True)

    assert gdb.execute("eq $sp 0xbabe 0xcafe", to_string=True) == ""
    assert "0x000000000000babe\t0x000000000000cafe" in gdb.execute("x/2xg $sp", to_string=True)

    assert gdb.execute("eq $sp cafe000000000000 babe000000000000", to_string=True) == ""
    assert "0xcafe000000000000\t0xbabe000000000000" in gdb.execute("x/2xg $sp", to_string=True)

    # TODO/FIXME: implement tests for others (ed, ew, eb etc)

    #########################################
    ### Test write & output on partial write
    #########################################
    # e.g. when we make a write to the last stack address
    stack_ea = pwndbg.aglib.regs[pwndbg.aglib.regs.stack]
    stack_page = pwndbg.aglib.vmmap.find(stack_ea)

    # Last possible address on stack where we can perform an 8-byte write
    stack_last_qword_ea = stack_page.end - 8

    gdb_result = gdb.execute(
        "eq %#x 0xCAFEBABEdeadbeef 0xABCD" % stack_last_qword_ea, to_string=True
    ).split("\n")
    assert "Cannot access memory at address" in gdb_result[0]
    assert gdb_result[1] == "(Made 1 writes to memory; skipping further writes)"

    # Check if the write actually occurred
    assert pwndbg.aglib.memory.read(stack_last_qword_ea, 8) == b"\xef\xbe\xad\xde\xbe\xba\xfe\xca"


def test_windbg_commands_x86(start_binary):
    """
    Tests windbg compatibility commands that dump memory
    like dq, dw, db, ds etc.
    """
    start_binary(X86_BINARY)

    # Prepare memory
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp, b"1234567890abcdef_")
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp + 16, b"\x00" * 16)
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp + 32, bytes(range(16)))
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp + 48, b"Z" * 16)

    #################################################
    #### dX command tests
    #################################################
    db = gdb.execute("db $esp", to_string=True).splitlines()
    assert db == [
        "%x     31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66" % pwndbg.aglib.regs.esp,
        "%x     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" % (pwndbg.aglib.regs.esp + 16),
        "%x     00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    dw = gdb.execute("dw $esp", to_string=True).splitlines()
    assert dw == [
        "%x     3231 3433 3635 3837 3039 6261 6463 6665" % pwndbg.aglib.regs.esp,
        "%x     0000 0000 0000 0000 0000 0000 0000 0000" % (pwndbg.aglib.regs.esp + 16),
        "%x     0100 0302 0504 0706 0908 0b0a 0d0c 0f0e" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a5a 5a5a 5a5a 5a5a 5a5a 5a5a 5a5a 5a5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    dd = gdb.execute("dd $esp", to_string=True).splitlines()
    assert dd == [
        "%x     34333231 38373635 62613039 66656463" % pwndbg.aglib.regs.esp,
        "%x     00000000 00000000 00000000 00000000" % (pwndbg.aglib.regs.esp + 16),
        "%x     03020100 07060504 0b0a0908 0f0e0d0c" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a5a5a5a 5a5a5a5a 5a5a5a5a 5a5a5a5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    dq = gdb.execute("dq $esp", to_string=True).splitlines()
    assert dq == [
        "%x     3837363534333231 6665646362613039" % pwndbg.aglib.regs.esp,
        "%x     0000000000000000 0000000000000000" % (pwndbg.aglib.regs.esp + 16),
        "%x     0706050403020100 0f0e0d0c0b0a0908" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a5a5a5a5a5a5a5a 5a5a5a5a5a5a5a5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    #################################################
    #### eX command tests
    #################################################
    gdb.execute("eb $esp 00")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 1) == b"\x00"

    gdb.execute("ew $esp 4141")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 2) == b"\x41\x41"

    gdb.execute("ed $esp 5252525252")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 4) == b"\x52" * 4

    gdb.execute("eq $esp 1122334455667788")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 8) == b"\x88\x77\x66\x55\x44\x33\x22\x11"
