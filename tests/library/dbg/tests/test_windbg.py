from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

MEMORY_BINARY = get_binary("memory.out")
X86_BINARY = get_binary("gosample.x86")

data_addr = "0x401000"


@pwndbg_test
async def test_windbg_dX_commands(ctrl: Controller) -> None:
    """
    Tests windbg compatibility commands that dump memory
    like dq, dw, db, ds etc.
    """
    import pwndbg.aglib.regs

    await ctrl.launch(MEMORY_BINARY)

    # Try to fail commands in different way
    for cmd_prefix in ("dq", "dd", "dw", "db"):
        # With a non-existent symbol
        cmd = cmd_prefix + " nonexistentsymbol"
        assert (await ctrl.execute_and_capture(cmd)) == (
            "usage: XX [-h] address [count]\n"
            "XX: error: argument address: Incorrect address (or GDB expression): nonexistentsymbol\n"
        ).replace("XX", cmd_prefix)

        # With an invalid/unmapped address
        cmd = cmd_prefix + " 0"
        assert (await ctrl.execute_and_capture(cmd)) == "Could not access the provided address\n"

    #################################################
    #### dq command tests
    #################################################
    # Try `dq` with symbol, &symbol, 0x<address> and <address> without 0x prefix (treated as hex!)
    dq1 = await ctrl.execute_and_capture("dq data")
    dq2 = await ctrl.execute_and_capture("dq &data")
    dq3 = await ctrl.execute_and_capture(f"dq {data_addr}")
    dq4 = await ctrl.execute_and_capture(f"dq {data_addr.replace('0x', '')}")
    assert (
        dq1
        == dq2
        == dq3
        == dq4
        == (
            "0000000000401000     0000000000000000 0000000000000001\n"
            "0000000000401010     0000000100000002 0001000200030004\n"
            "0000000000401020     0102030405060708 1122334455667788\n"
            "0000000000401030     0123456789abcdef 0000000000000000\n"
        )
    )

    # Try `dq` with different counts
    dq_count1 = await ctrl.execute_and_capture("dq data 2")
    dq_count2 = await ctrl.execute_and_capture("dq &data 2")
    dq_count3 = await ctrl.execute_and_capture(f"dq {data_addr} 2")
    assert (
        dq_count1
        == dq_count2
        == dq_count3
        == "0000000000401000     0000000000000000 0000000000000001\n"
    )

    assert (
        await ctrl.execute_and_capture("dq data 1")
    ) == "0000000000401000     0000000000000000\n"
    assert (await ctrl.execute_and_capture("dq data 3")) == (
        "0000000000401000     0000000000000000 0000000000000001\n"
        "0000000000401010     0000000100000002\n"
    )

    # Try 'dq' with count equal to a register, but lets set it before ;)
    # also note that we use `data2` here
    pwndbg.aglib.regs.eax = 4
    assert (await ctrl.execute_and_capture("dq data2 $eax")) == (
        "0000000000401028     1122334455667788 0123456789abcdef\n"
        "0000000000401038     0000000000000000 ffffffffffffffff\n"
    )

    # See if we can repeat dq command (use count for shorter data)
    assert (await ctrl.execute_and_capture("dq data2 2")) == (
        "0000000000401028     1122334455667788 0123456789abcdef\n"
    )

    # TODO/FIXME: Can we test command repeating here? Neither passing `from_tty=True`
    # or setting `pwndbg.commands.windbg.dq.repeat = True` works here
    # assert await ctrl.execute_and_capture('dq data2 2') == (
    #    '00000000004000b9     0000000000000000 ffffffffffffffff\n'
    # )

    #################################################
    #### dd command tests
    #################################################
    dd1 = await ctrl.execute_and_capture("dd data")
    dd2 = await ctrl.execute_and_capture("dd &data")
    dd3 = await ctrl.execute_and_capture(f"dd {data_addr}")
    dd4 = await ctrl.execute_and_capture(f"dd {data_addr.replace('0x', '')}")
    assert (
        dd1
        == dd2
        == dd3
        == dd4
        == (
            "0000000000401000     00000000 00000000 00000001 00000000\n"
            "0000000000401010     00000002 00000001 00030004 00010002\n"
            "0000000000401020     05060708 01020304 55667788 11223344\n"
            "0000000000401030     89abcdef 01234567 00000000 00000000\n"
        )
    )

    # count tests
    assert (await ctrl.execute_and_capture("dd data 4")) == (
        "0000000000401000     00000000 00000000 00000001 00000000\n"
    )
    assert (await ctrl.execute_and_capture("dd data 3")) == (
        "0000000000401000     00000000 00000000 00000001\n"
    )

    #################################################
    #### dw command tests
    #################################################
    dw1 = await ctrl.execute_and_capture("dw data")
    dw2 = await ctrl.execute_and_capture("dw &data")
    dw3 = await ctrl.execute_and_capture(f"dw {data_addr}")
    dw4 = await ctrl.execute_and_capture(f"dw {data_addr.replace('0x', '')}")
    assert (
        dw1
        == dw2
        == dw3
        == dw4
        == (
            "0000000000401000     0000 0000 0000 0000 0001 0000 0000 0000\n"
            "0000000000401010     0002 0000 0001 0000 0004 0003 0002 0001\n"
            "0000000000401020     0708 0506 0304 0102 7788 5566 3344 1122\n"
            "0000000000401030     cdef 89ab 4567 0123 0000 0000 0000 0000\n"
        )
    )

    # count tests
    assert (await ctrl.execute_and_capture("dw data 8")) == (
        "0000000000401000     0000 0000 0000 0000 0001 0000 0000 0000\n"
    )

    assert (await ctrl.execute_and_capture("dw data 8/2")) == (
        "0000000000401000     0000 0000 0000 0000\n"
    )

    assert (await ctrl.execute_and_capture("dw data $eax")) == (
        "0000000000401000     0000 0000 0000 0000\n"
    )

    #################################################
    #### db command tests
    #################################################
    db1 = await ctrl.execute_and_capture("db data")
    db2 = await ctrl.execute_and_capture("db &data")
    db3 = await ctrl.execute_and_capture(f"db {data_addr}")
    db4 = await ctrl.execute_and_capture(f"db {data_addr.replace('0x', '')}")
    assert (
        db1
        == db2
        == db3
        == db4
        == (
            "0000000000401000     00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00\n"
            "0000000000401010     02 00 00 00 01 00 00 00 04 00 03 00 02 00 01 00\n"
            "0000000000401020     08 07 06 05 04 03 02 01 88 77 66 55 44 33 22 11\n"
            "0000000000401030     ef cd ab 89 67 45 23 01 00 00 00 00 00 00 00 00\n"
        )
    )

    # count tests
    assert (await ctrl.execute_and_capture("db data 31")) == (
        "0000000000401000     00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00\n"
        "0000000000401010     02 00 00 00 01 00 00 00 04 00 03 00 02 00 01\n"
    )
    assert (await ctrl.execute_and_capture("db data $ax")) == ("0000000000401000     00 00 00 00\n")

    #################################################
    #### dc command tests
    #################################################
    dc1 = await ctrl.execute_and_capture("dc data")
    dc2 = await ctrl.execute_and_capture("dc &data")
    dc3 = await ctrl.execute_and_capture(f"dc {data_addr}")
    dc4 = await ctrl.execute_and_capture(f"dc {data_addr.replace('0x', '')}")
    assert (
        dc1
        == dc2
        == dc3
        == dc4
        == (
            "+0000 0x401000  00 00 00 00 00 00 00 00                           "
            "│........│        │\n"
        )
    )

    assert (await ctrl.execute_and_capture("dc data 3")) == (
        "+0000 0x401000  00 00 00                                          │...     │        │\n"
    )

    #################################################
    #### ds command tests
    #################################################
    ds1 = await ctrl.execute_and_capture("ds short_str")
    ds2 = await ctrl.execute_and_capture("ds &short_str")
    ds3 = await ctrl.execute_and_capture("ds 0x401058")
    ds4 = await ctrl.execute_and_capture("ds 401058")
    assert ds1 == ds2 == ds3 == ds4 == "401058 'some cstring here'\n"

    # Check too low maxlen
    assert (await ctrl.execute_and_capture("ds short_str 5")) == (
        "Max str len of 5 too low, changing to 256\n401058 'some cstring here'\n"
    )

    # Check output for a string longer than (the default) maxlen of 256
    assert (await ctrl.execute_and_capture("ds long_str")) == (
        "40106a 'long string: "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...'\n"
    )

    # Check impossible address
    assert (await ctrl.execute_and_capture("ds 0")) == (
        "Data at address can't be dereferenced or is not a printable null-terminated "
        "string or is too short.\n"
        "Perhaps try: db <address> <count> or hexdump <address>\n"
    )


@pwndbg_test
async def test_windbg_eX_commands(ctrl: Controller) -> None:
    """
    Tests windbg compatibility commands that write to memory
    like eq, ed, ew, eb etc.
    """
    import pwndbg

    await ctrl.launch(MEMORY_BINARY)

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

        assert (await ctrl.execute_and_capture(cmd)) in expected_in
        assert (await ctrl.execute_and_capture(cmd)) in expected_in

        # With no data arguments provided
        cmd = cmd_prefix + " 0"
        assert (await ctrl.execute_and_capture(cmd)) == "Cannot write empty data into memory.\n"

        # With invalid/unmapped address 0
        cmd = cmd_prefix + " 0 1122"
        assert (await ctrl.execute_and_capture(cmd)) == ("Cannot access memory at address 0x0\n")

        # With invalid data which can't be parsed as hex
        cmd = cmd_prefix + " 0 x"
        assert (await ctrl.execute_and_capture(cmd)) == (
            "Incorrect data format: it must all be a hex value (0x1234 or 1234, both "
            "interpreted as 0x1234)\n"
        )
    #########################################
    ### Test eq write
    #########################################
    assert (await ctrl.execute_and_capture("eq $sp 0xcafebabe")) == ""
    assert "0x00000000cafebabe" in (await ctrl.execute_and_capture("x/xg $sp"))

    assert (await ctrl.execute_and_capture("eq $sp 0xbabe 0xcafe")) == ""
    assert re.search(
        "0x000000000000babe\\s+0x000000000000cafe", await ctrl.execute_and_capture("x/2xg $sp")
    )

    assert (await ctrl.execute_and_capture("eq $sp cafe000000000000 babe000000000000")) == ""
    assert re.search(
        "0xcafe000000000000\\s+0xbabe000000000000", await ctrl.execute_and_capture("x/2xg $sp")
    )

    # TODO/FIXME: implement tests for others (ed, ew, eb etc)

    #########################################
    ### Test write & output on partial write
    #########################################
    # e.g. when we make a write to the last stack address
    stack_ea = pwndbg.aglib.regs[pwndbg.aglib.regs.stack]
    stack_page = pwndbg.aglib.vmmap.find(stack_ea)

    # Last possible address on stack where we can perform an 8-byte write
    stack_last_qword_ea = stack_page.end - 8

    gdb_result = (
        await ctrl.execute_and_capture("eq %#x 0xCAFEBABEdeadbeef 0xABCD" % stack_last_qword_ea)
    ).split("\n")
    assert "Cannot access memory at address" in gdb_result[0]
    assert gdb_result[1] == "(Made 1 writes to memory; skipping further writes)"

    # Check if the write actually occurred
    assert pwndbg.aglib.memory.read(stack_last_qword_ea, 8) == b"\xef\xbe\xad\xde\xbe\xba\xfe\xca"


@pwndbg_test
async def test_windbg_commands_x86(ctrl: Controller) -> None:
    """
    Tests windbg compatibility commands that dump memory
    like dq, dw, db, ds etc.
    """
    import pwndbg
    from pwndbg.dbg import DebuggerType

    if pwndbg.dbg.name() == DebuggerType.LLDB:
        pytest.skip(
            "LLDB does not properly support Go, and fails to resolve expressions such as `$esp`"
        )
        return

    await ctrl.launch(X86_BINARY)

    # Prepare memory
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp, b"1234567890abcdef_")
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp + 16, b"\x00" * 16)
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp + 32, bytes(range(16)))
    pwndbg.aglib.memory.write(pwndbg.aglib.regs.esp + 48, b"Z" * 16)

    #################################################
    #### dX command tests
    #################################################
    db = (await ctrl.execute_and_capture("db $esp")).splitlines()
    assert db == [
        "%x     31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66" % pwndbg.aglib.regs.esp,
        "%x     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" % (pwndbg.aglib.regs.esp + 16),
        "%x     00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    dw = (await ctrl.execute_and_capture("dw $esp")).splitlines()
    assert dw == [
        "%x     3231 3433 3635 3837 3039 6261 6463 6665" % pwndbg.aglib.regs.esp,
        "%x     0000 0000 0000 0000 0000 0000 0000 0000" % (pwndbg.aglib.regs.esp + 16),
        "%x     0100 0302 0504 0706 0908 0b0a 0d0c 0f0e" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a5a 5a5a 5a5a 5a5a 5a5a 5a5a 5a5a 5a5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    dd = (await ctrl.execute_and_capture("dd $esp")).splitlines()
    assert dd == [
        "%x     34333231 38373635 62613039 66656463" % pwndbg.aglib.regs.esp,
        "%x     00000000 00000000 00000000 00000000" % (pwndbg.aglib.regs.esp + 16),
        "%x     03020100 07060504 0b0a0908 0f0e0d0c" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a5a5a5a 5a5a5a5a 5a5a5a5a 5a5a5a5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    dq = (await ctrl.execute_and_capture("dq $esp")).splitlines()
    assert dq == [
        "%x     3837363534333231 6665646362613039" % pwndbg.aglib.regs.esp,
        "%x     0000000000000000 0000000000000000" % (pwndbg.aglib.regs.esp + 16),
        "%x     0706050403020100 0f0e0d0c0b0a0908" % (pwndbg.aglib.regs.esp + 32),
        "%x     5a5a5a5a5a5a5a5a 5a5a5a5a5a5a5a5a" % (pwndbg.aglib.regs.esp + 48),
    ]

    #################################################
    #### eX command tests
    #################################################
    await ctrl.execute("eb $esp 00")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 1) == b"\x00"

    await ctrl.execute("ew $esp 4141")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 2) == b"\x41\x41"

    await ctrl.execute("ed $esp 5252525252")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 4) == b"\x52" * 4

    await ctrl.execute("eq $esp 1122334455667788")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.esp, 8) == b"\x88\x77\x66\x55\x44\x33\x22\x11"
