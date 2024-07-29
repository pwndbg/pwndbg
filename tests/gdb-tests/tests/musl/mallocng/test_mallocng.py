from __future__ import annotations

import gdb

import pwndbg
import pwndbg.lib.strings
import tests

HEAP_BINARY = tests.binaries.get("musl_mallocng_initialized.out")


def get_stride_0x10_slot_addr(mheapinfo_output):
    slot_addr = None
    for line in mheapinfo_output.splitlines():
        if "active.[0]" in line:
            # Expect line to be of form: active.[0] : 0x2040e0 (mem: 0x7ffff7ffecb0) [0x10]
            # Get 0x7ffff7ffecb0) [0x10]
            slot_addr = line.split("mem:")[-1]
            if not slot_addr:
                raise Exception("Could not find slot address. Expected (mem: ...) missing")
            # Get 0x7ffff7ffecb0
            slot_addr = slot_addr.split(")")[0]
            if not slot_addr:
                raise Exception("Could not find slot address. Expected (mem: ...) missing")
            break
    return slot_addr


def check_meta_output(output):
    # Check ================== META ================== fields
    for expected in [
        "prev",
        "next",
        "mem",
        "last_idx",
        "avail_mask",
        "freed_mask",
        "area->check",
        "sizeclass",
        "maplen",
        "freeable",
    ]:
        assert f"{expected} :" in output


def test_musl_mallocng(start_binary):
    """Make sure we can execute any mallocng command"""
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # print(gdb.execute("!pwd"))
    # gdb.execute("add-symbol-file tests/binaries/musls/1.2.4/lib/ld-musl-x86_64.so.1.debug")
    # gdb.execute("info sharedlibrary")
    malloc_context = pwndbg.gdblib.symbol.address("__malloc_context")
    assert malloc_context is not None

    # Make sure at least one command works
    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    assert "secret" in mheapinfo_output


def test_musl_mallocng_mheapinfo(start_binary):
    """Make sure all expected fields are output"""

    start_binary(HEAP_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Make sure most expected fields are output
    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    mheapinfo_output = pwndbg.lib.strings.strip_colors(mheapinfo_output)
    for expected in [
        "secret",
        "mmap_counter",
        "avail_meta",
        "free_meta",
        "avail_meta_area",
        "meta_area_head",
        "meta_area_tail",
        "active.[0]",
    ]:
        assert f"{expected} :" in mheapinfo_output

    # Make sure the base active group is stride 0x10
    for line in mheapinfo_output.splitlines():
        if "active.[0]" in line:
            assert line.endswith("[0x10]")


def test_musl_mallocng_mslotfind(start_binary):
    """Test that mslotfind on a valid slot outputs expected values"""

    # First use mheapinfo to find an active group to query for a slot to find
    start_binary(HEAP_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # FIXME: We could create a helper to combine these, as it will be common
    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    mheapinfo_output = pwndbg.lib.strings.strip_colors(mheapinfo_output)
    slot_addr = get_stride_0x10_slot_addr(mheapinfo_output)

    mfindslot_output = gdb.execute(f"mfindslot {slot_addr}", to_string=True)
    mfindslot_output = pwndbg.lib.strings.strip_colors(mfindslot_output)
    assert "Found: slot index is" in mfindslot_output

    # Check ================== SLOT OUT-OF-BAND ================== fields
    for expected in ["address", "index", "stride", "meta obj", "status"]:
        assert f"{expected} :" in mfindslot_output

    check_meta_output(mfindslot_output)
    assert (
        "(stride: 0x10)" in mfindslot_output
    )  # We grabbed a active.[0] slot above, so expect this to match


def test_musl_mallocng_mslotinfo(start_binary):
    start_binary(HEAP_BINARY)
    gdb.execute("break break_here")
    gdb.execute("continue")

    mheapinfo_output = gdb.execute("mheapinfo", to_string=True)
    mheapinfo_output = pwndbg.lib.strings.strip_colors(mheapinfo_output)
    slot_addr = get_stride_0x10_slot_addr(mheapinfo_output)
    mslotinfo_output = gdb.execute(f"mslotinfo {slot_addr}", to_string=True)
    mslotinfo_output = pwndbg.lib.strings.strip_colors(mslotinfo_output)

    # Check ============== IN-BAND META ==============
    for expected in ["INDEX", "RESERVED", "OVERFLOW"]:
        assert f"{expected} :" in mslotinfo_output
    assert "OFFSET_16" in mslotinfo_output or "OFFSET_32" in mslotinfo_output

    # Check ============== GROUP ==============
    for expected in ["meta", "active_idx"]:
        assert f"{expected} :" in mslotinfo_output

    check_meta_output(mslotinfo_output)

    assert "Group allocation method : " in mslotinfo_output

    # Check ================== SLOT IN-BAND ============
    for expected in [
        "nominal size",
        # "reserved size",
        "OVERFLOW (user data)",
        "OVERFLOW (next slot)",
    ]:
        assert f"{expected} :" in mslotinfo_output
