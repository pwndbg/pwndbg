from __future__ import annotations

import gdb

import tests

MMAP_GAPS_BINARY = tests.binaries.get("mmap_gaps.out")


def test_dump_mmap_args(start_binary):
    """
    Tests dumpargs command on an xmmap call
    """
    start_binary(MMAP_GAPS_BINARY)

    # Run until main
    gdb.execute("break main")
    gdb.execute("continue")

    # Stop on xmmap(...)
    gdb.execute("nextcall")
    # Step into the xmmap(...) call
    gdb.execute("step")
    # Stop on mmap(...)
    gdb.execute("nextcall")

    out = gdb.execute("dumpargs", to_string=True).splitlines()
    assert len(out) == 6
    assert out[0] == "        addr:      0xcafe0000"
    assert out[1] == "        len:       0x1000"
    assert out[2] == "        prot:      1"
    assert out[3] == "        flags:     0x32 (MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED)"
    assert out[4] == "        fd:        0xffffffff"
    assert out[5] == "        offset:    0"
