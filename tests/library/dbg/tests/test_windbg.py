from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

MEMORY_BINARY = get_binary("memory.native.out")
X86_BINARY = get_binary("gosample.i386.out")


@pwndbg_test
async def test_windbg_dX_commands(ctrl: Controller) -> None:
    """
    Tests windbg compatibility commands that dump memory
    like dq, dw, db, ds etc.
    """
    import pwndbg
    import pwndbg.aglib
    from pwndbg.dbg_mod import DebuggerType

    await ctrl.launch(MEMORY_BINARY)

    inf = pwndbg.dbg.selected_inferior()
    data_addr = hex(int(inf.lookup_symbol("data")))
    short_str_addr = hex(int(inf.lookup_symbol("short_str")))
    long_str_addr = hex(int(inf.lookup_symbol("long_str")))

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

    data_addr_int = int(data_addr, 16)
    expected_dq = (
        f"{data_addr_int:016x}     0000000000000000 0000000000000001\n"
        f"{data_addr_int + 0x10:016x}     0000000100000002 0001000200030004\n"
        f"{data_addr_int + 0x20:016x}     0102030405060708 1122334455667788\n"
        f"{data_addr_int + 0x30:016x}     0123456789abcdef 0000000000000000\n"
    )
    assert dq1 == dq2 == dq3 == dq4 == expected_dq

    # Try `dq` with different counts
    dq_count1 = await ctrl.execute_and_capture("dq data 2")
    dq_count2 = await ctrl.execute_and_capture("dq &data 2")
    dq_count3 = await ctrl.execute_and_capture(f"dq {data_addr} 2")
    assert (
        dq_count1
        == dq_count2
        == dq_count3
        == f"{data_addr_int:016x}     0000000000000000 0000000000000001\n"
    )

    assert (
        await ctrl.execute_and_capture("dq data 1")
        == f"{data_addr_int:016x}     0000000000000000\n"
    )
    assert (await ctrl.execute_and_capture("dq data 3")) == (
        f"{data_addr_int:016x}     0000000000000000 0000000000000001\n"
        f"{data_addr_int + 0x10:016x}     0000000100000002\n"
    )

    # Try 'dq' with count equal to a register, but lets set it before ;)
    # also note that we use `data2` here
    data2_addr_int = int(inf.lookup_symbol("data2"))
    # Use architecture-appropriate register (eax for x86, w0 for aarch64)
    test_reg_32 = "w0" if pwndbg.aglib.arch.name == "aarch64" else "eax"
    pwndbg.aglib.regs.write_reg(test_reg_32, 4)
    assert (await ctrl.execute_and_capture(f"dq data2 ${test_reg_32}")) == (
        f"{data2_addr_int:016x}     1122334455667788 0123456789abcdef\n"
        f"{data2_addr_int + 0x10:016x}     0000000000000000 ffffffffffffffff\n"
    )

    # See if we can repeat dq command (use count for shorter data)
    assert (
        await ctrl.execute_and_capture("dq data2 2")
    ) == f"{data2_addr_int:016x}     1122334455667788 0123456789abcdef\n"

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
    expected_dd = (
        f"{data_addr_int:016x}     00000000 00000000 00000001 00000000\n"
        f"{data_addr_int + 0x10:016x}     00000002 00000001 00030004 00010002\n"
        f"{data_addr_int + 0x20:016x}     05060708 01020304 55667788 11223344\n"
        f"{data_addr_int + 0x30:016x}     89abcdef 01234567 00000000 00000000\n"
    )
    assert dd1 == dd2 == dd3 == dd4 == expected_dd

    # count tests
    assert (
        await ctrl.execute_and_capture("dd data 4")
    ) == f"{data_addr_int:016x}     00000000 00000000 00000001 00000000\n"
    assert (
        await ctrl.execute_and_capture("dd data 3")
    ) == f"{data_addr_int:016x}     00000000 00000000 00000001\n"

    #################################################
    #### dw command tests
    #################################################
    dw1 = await ctrl.execute_and_capture("dw data")
    dw2 = await ctrl.execute_and_capture("dw &data")
    dw3 = await ctrl.execute_and_capture(f"dw {data_addr}")
    dw4 = await ctrl.execute_and_capture(f"dw {data_addr.replace('0x', '')}")
    expected_dw = (
        f"{data_addr_int:016x}     0000 0000 0000 0000 0001 0000 0000 0000\n"
        f"{data_addr_int + 0x10:016x}     0002 0000 0001 0000 0004 0003 0002 0001\n"
        f"{data_addr_int + 0x20:016x}     0708 0506 0304 0102 7788 5566 3344 1122\n"
        f"{data_addr_int + 0x30:016x}     cdef 89ab 4567 0123 0000 0000 0000 0000\n"
    )
    assert dw1 == dw2 == dw3 == dw4 == expected_dw

    # count tests
    assert (
        await ctrl.execute_and_capture("dw data 8")
    ) == f"{data_addr_int:016x}     0000 0000 0000 0000 0001 0000 0000 0000\n"

    assert (
        await ctrl.execute_and_capture("dw data 8/2")
    ) == f"{data_addr_int:016x}     0000 0000 0000 0000\n"

    assert (
        await ctrl.execute_and_capture(f"dw data ${test_reg_32}")
    ) == f"{data_addr_int:016x}     0000 0000 0000 0000\n"

    #################################################
    #### db command tests
    #################################################
    db1 = await ctrl.execute_and_capture("db data")
    db2 = await ctrl.execute_and_capture("db &data")
    db3 = await ctrl.execute_and_capture(f"db {data_addr}")
    db4 = await ctrl.execute_and_capture(f"db {data_addr.replace('0x', '')}")
    expected_db = (
        f"{data_addr_int:016x}     00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00\n"
        f"{data_addr_int + 0x10:016x}     02 00 00 00 01 00 00 00 04 00 03 00 02 00 01 00\n"
        f"{data_addr_int + 0x20:016x}     08 07 06 05 04 03 02 01 88 77 66 55 44 33 22 11\n"
        f"{data_addr_int + 0x30:016x}     ef cd ab 89 67 45 23 01 00 00 00 00 00 00 00 00\n"
    )
    assert db1 == db2 == db3 == db4 == expected_db

    # count tests
    assert (await ctrl.execute_and_capture("db data 31")) == (
        f"{data_addr_int:016x}     00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00\n"
        f"{data_addr_int + 0x10:016x}     02 00 00 00 01 00 00 00 04 00 03 00 02 00 01\n"
    )
    # Use 16-bit register (ax for x86, w0 for aarch64 as it doesn't have 16-bit regs)
    test_reg_16 = "w0" if pwndbg.aglib.arch.name == "aarch64" else "ax"
    assert (
        await ctrl.execute_and_capture(f"db data ${test_reg_16}")
    ) == f"{data_addr_int:016x}     00 00 00 00\n"

    #################################################
    #### dc command tests
    #################################################
    dc1 = await ctrl.execute_and_capture("dc data")
    dc2 = await ctrl.execute_and_capture("dc &data")
    dc3 = await ctrl.execute_and_capture(f"dc {data_addr}")
    dc4 = await ctrl.execute_and_capture(f"dc {data_addr.replace('0x', '')}")
    expected_dc = f"+0000 {data_addr}  00 00 00 00 00 00 00 00                           │........│        │\n"
    assert dc1 == dc2 == dc3 == dc4 == expected_dc

    assert (
        (await ctrl.execute_and_capture("dc data 3"))
        == f"+0000 {data_addr}  00 00 00                                          │...     │        │\n"
    )

    #################################################
    #### ds command tests
    #################################################
    ds1 = await ctrl.execute_and_capture("ds short_str")
    ds2 = await ctrl.execute_and_capture("ds &short_str")
    ds3 = await ctrl.execute_and_capture(f"ds {short_str_addr}")
    ds4 = await ctrl.execute_and_capture(f"ds {short_str_addr.replace('0x', '')}")
    short_str_addr_int = int(short_str_addr, 16)
    assert ds1 == ds2 == ds3 == ds4 == f"{short_str_addr_int:x} 'some cstring here'\n"

    # Check too low maxlen
    assert (await ctrl.execute_and_capture("ds short_str 5")) == (
        f"Max str len of 5 too low, changing to 256\n{short_str_addr_int:x} 'some cstring here'\n"
    )

    # Check output for a string longer than (the default) maxlen of 256
    long_str_addr_int = int(long_str_addr, 16)
    assert (await ctrl.execute_and_capture("ds long_str")) == (
        f"{long_str_addr_int:x} 'long string: "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...'\n"
    )

    # Check impossible address
    assert (await ctrl.execute_and_capture("ds 0")) == (
        "Data at address can't be dereferenced or is not a printable null-terminated "
        "string or is too short.\n"
        "Perhaps try: db <address> <count> or hexdump <address>\n"
    )

    #################################################
    #### dds / dps / dqs / kd command tests
    #################################################
    for cmd in ("dds", "dps", "dqs", "kd"):
        # Without count argument (uses default)
        out_default = (await ctrl.execute_and_capture(f"{cmd} &data")).strip().splitlines()
        # With count argument
        out_3 = (await ctrl.execute_and_capture(f"{cmd} &data 3")).strip().splitlines()
        assert len(out_3) == 3
        # Ensure the first lines of both are identical
        assert out_default[:3] == out_3

    # Test repeat/Enter behavior by mocking check_repeated to return True (only on GDB)
    is_gdb = pwndbg.dbg.name() == DebuggerType.GDB
    if is_gdb:
        out_normal = (await ctrl.execute_and_capture("dds &data 2")).strip().splitlines()
        await ctrl.execute("pi pwndbg.commands.windbg.dds.check_repeated = lambda *a, **kw: True")
        try:
            out_repeated = (await ctrl.execute_and_capture("dds &data 2")).strip().splitlines()
            # Verify it has different addresses
            assert out_normal != out_repeated
            # Verify it dumped consecutive memory regions (e.g. out_repeated starts after out_normal ends)
            ptrsize = pwndbg.aglib.typeinfo.ptrsize
            addr_normal_start = int(out_normal[0].split()[1], 16)
            addr_repeated_start = int(out_repeated[0].split()[1], 16)
            assert addr_repeated_start == addr_normal_start + 2 * ptrsize
        finally:
            await ctrl.execute("pi del pwndbg.commands.windbg.dds.check_repeated")


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
    stack_ea = pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.stack)
    stack_page = pwndbg.aglib.vmmap.find(stack_ea)

    # Last possible address on stack where we can perform an 8-byte write
    stack_last_qword_ea = stack_page.end - 8

    gdb_result = (
        await ctrl.execute_and_capture(f"eq {stack_last_qword_ea:#x} 0xCAFEBABEdeadbeef 0xABCD")
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
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() == DebuggerType.LLDB:
        pytest.skip(
            "LLDB does not properly support Go, and fails to resolve expressions such as `$esp`"
        )
        return

    await ctrl.launch(X86_BINARY)

    esp = pwndbg.aglib.regs.read_reg("esp")

    # Prepare memory
    pwndbg.aglib.memory.write(esp, b"1234567890abcdef_")
    pwndbg.aglib.memory.write(esp + 16, b"\x00" * 16)
    pwndbg.aglib.memory.write(esp + 32, bytes(range(16)))
    pwndbg.aglib.memory.write(esp + 48, b"Z" * 16)

    #################################################
    #### dX command tests
    #################################################
    db = (await ctrl.execute_and_capture("db $esp")).splitlines()
    esp = pwndbg.aglib.regs.read_reg("esp")
    assert db == [
        f"{esp:x}     31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66",
        f"{esp + 16:x}     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        f"{esp + 32:x}     00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
        f"{esp + 48:x}     5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a",
    ]

    dw = (await ctrl.execute_and_capture("dw $esp")).splitlines()
    esp = pwndbg.aglib.regs.read_reg("esp")
    assert dw == [
        f"{esp:x}     3231 3433 3635 3837 3039 6261 6463 6665",
        f"{esp + 16:x}     0000 0000 0000 0000 0000 0000 0000 0000",
        f"{esp + 32:x}     0100 0302 0504 0706 0908 0b0a 0d0c 0f0e",
        f"{esp + 48:x}     5a5a 5a5a 5a5a 5a5a 5a5a 5a5a 5a5a 5a5a",
    ]

    dd = (await ctrl.execute_and_capture("dd $esp")).splitlines()
    esp = pwndbg.aglib.regs.read_reg("esp")
    assert dd == [
        f"{esp:x}     34333231 38373635 62613039 66656463",
        f"{esp + 16:x}     00000000 00000000 00000000 00000000",
        f"{esp + 32:x}     03020100 07060504 0b0a0908 0f0e0d0c",
        f"{esp + 48:x}     5a5a5a5a 5a5a5a5a 5a5a5a5a 5a5a5a5a",
    ]

    dq = (await ctrl.execute_and_capture("dq $esp")).splitlines()
    esp = pwndbg.aglib.regs.read_reg("esp")
    assert dq == [
        f"{esp:x}     3837363534333231 6665646362613039",
        f"{esp + 16:x}     0000000000000000 0000000000000000",
        f"{esp + 32:x}     0706050403020100 0f0e0d0c0b0a0908",
        f"{esp + 48:x}     5a5a5a5a5a5a5a5a 5a5a5a5a5a5a5a5a",
    ]

    #################################################
    #### eX command tests
    #################################################
    await ctrl.execute("eb $esp 00")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.read_reg("esp"), 1) == b"\x00"

    await ctrl.execute("ew $esp 4141")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.read_reg("esp"), 2) == b"\x41\x41"

    await ctrl.execute("ed $esp 5252525252")
    assert pwndbg.aglib.memory.read(pwndbg.aglib.regs.read_reg("esp"), 4) == b"\x52" * 4

    await ctrl.execute("eq $esp 1122334455667788")
    assert (
        pwndbg.aglib.memory.read(pwndbg.aglib.regs.read_reg("esp"), 8)
        == b"\x88\x77\x66\x55\x44\x33\x22\x11"
    )
