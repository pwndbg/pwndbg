from __future__ import annotations

import re

import gdb
import pytest

import pwndbg.color as color
import tests

HEAP_MALLOCNG_DYN = tests.get_binary("heap_musl_dyn.out")
HEAP_MALLOCNG_STATIC = tests.get_binary("heap_musl_static.out")

# Userland only
re_addr = r"0x[0-9a-fA-F]{1,12}"


@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
def test_mallocng_slot_user(start_binary, binary):
    start_binary(binary)

    gdb.execute("break break_here")

    gdb.execute("continue")
    gdb.execute("finish")  # Get out of the break_here() function.

    # == Check generic command output ==

    buffer4_out = gdb.execute("ng-slotu buffer1", to_string=True).splitlines()

    # Strip the colors. FIXME: After #3142 is figured out.
    buffer4_out = [color.strip(x) for x in buffer4_out]

    expected_output = [
        "slab",
        f"  group:          {re_addr}    ",
        f"  meta:           {re_addr}    ",
        "general",
        f"  start:          {re_addr}    ",
        f"  user start:     {re_addr}    aka `p`",
        rf"  end:            {re_addr}    start \+ stride - 4",
        "  stride:         0x30              distance between adjacent slots",
        """  user size:      0x20              aka "nominal size", `n`""",
        r"  slack:          0x0 \(0x0\)         slot's unused memory \/ 0x10",
        "in-band",
        r"  offset:         0x[0-9] \(0x[0-9]{0,1}0\)         distance to first slot start \/ 0x10",
        r"  index:          0x0               index of slot in its group",
        "  hdr reserved:   0x5               describes: end - p - n",
        "                                    use ftr reserved",
        "  ftr reserved:   0xc               ",
        r"  cyclic offset:  NA \(not cyclic\)   prevents double free, \(p - start\) / 0x10",
        "",
        r"The slot is \(probably\) allocated.",
    ]

    for i in range(len(expected_output)):
        assert re.match(expected_output[i], buffer4_out[i])

    # == Check various fields ==
    buffer2_out = color.strip(gdb.execute("ng-slotu buffer2", to_string=True)).splitlines()
    buffer4_out = color.strip(gdb.execute("ng-slotu buffer4", to_string=True)).splitlines()

    stride_idx = 7
    user_size_idx = 8
    slack_idx = 9
    offset_idx = 11
    index_idx = 12
    hdr_res_idx = 13
    ftr_res_idx = 15
    cyclic_idx = 16
    status_idx = 18

    # Check stride
    assert "stride" in buffer2_out[stride_idx] and " 0x30 " in buffer2_out[stride_idx]
    assert "stride" in buffer4_out[stride_idx] and " 0x2a0 " in buffer4_out[stride_idx]

    # Check user size
    assert "user size" in buffer2_out[user_size_idx] and " 0x20 " in buffer2_out[user_size_idx]
    assert "user size" in buffer4_out[user_size_idx] and " 0x211 " in buffer4_out[user_size_idx]

    # Check slack
    assert "slack" in buffer2_out[slack_idx] and " 0x0 " in buffer2_out[slack_idx]
    assert "slack" in buffer4_out[slack_idx] and " 0x8 (0x80) " in buffer4_out[slack_idx]

    # Check offset
    assert "offset" in buffer2_out[offset_idx] and " 0x3 (0x30) " in buffer2_out[offset_idx]
    if binary == HEAP_MALLOCNG_STATIC:
        # Because it's cyclic
        assert "offset" in buffer4_out[offset_idx] and " 0x1 (0x10) " in buffer4_out[offset_idx]
    else:
        assert "offset" in buffer4_out[offset_idx] and " 0x0 (0x0) " in buffer4_out[offset_idx]

    # Check index
    assert "index" in buffer2_out[index_idx] and " 0x1 " in buffer2_out[index_idx]
    assert "index" in buffer4_out[index_idx] and " 0x0 " in buffer4_out[index_idx]

    # Check reserved
    assert "hdr reserved" in buffer2_out[hdr_res_idx] and " 0x5 " in buffer2_out[hdr_res_idx]
    assert "hdr reserved" in buffer4_out[hdr_res_idx] and " 0x5 " in buffer4_out[hdr_res_idx]
    assert "use ftr reserved" in buffer2_out[hdr_res_idx + 1]
    assert "use ftr reserved" in buffer4_out[hdr_res_idx + 1]
    assert "ftr reserved" in buffer2_out[ftr_res_idx] and " 0xc " in buffer2_out[ftr_res_idx]
    if binary == HEAP_MALLOCNG_STATIC:
        assert "ftr reserved" in buffer4_out[ftr_res_idx] and " 0x7b " in buffer4_out[ftr_res_idx]
    else:
        assert "ftr reserved" in buffer4_out[ftr_res_idx] and " 0x8b " in buffer4_out[ftr_res_idx]

    # Check cyclic
    assert (
        "cyclic offset" in buffer2_out[cyclic_idx]
        and " NA (not cyclic) " in buffer2_out[cyclic_idx]
    )
    if binary == HEAP_MALLOCNG_STATIC:
        assert (
            "cyclic offset" in buffer4_out[cyclic_idx] and " 0x1 (0x10) " in buffer4_out[cyclic_idx]
        )
    else:
        assert (
            "cyclic offset" in buffer4_out[cyclic_idx]
            and " NA (not cyclic) " in buffer4_out[cyclic_idx]
        )

    # Check allocation status
    assert "slot is" in buffer2_out[status_idx] and " allocated." in buffer2_out[status_idx]
    assert "slot is" in buffer4_out[status_idx] and " allocated." in buffer4_out[status_idx]

    # == Check command on free slots ==
    gdb.execute("continue")
    gdb.execute("continue")
    gdb.execute("finish")

    buffer2_out = color.strip(gdb.execute("ng-slotu buffer2", to_string=True))

    # Make sure we found the thingy even though it is invalid locally.
    assert (
        "Could not load valid meta from local"
        " information, searching the heap.. Found it." in buffer2_out
    )
    assert "Local slot memory:" in buffer2_out
    assert "Slot information from the group/meta:" in buffer2_out

    # Check we correctly detected slot state
    assert "state:          freed" in buffer2_out

    gdb.execute("continue")
    gdb.execute("finish")

    # Now buffer3 got free()'d and so did the group which contained buffer{1,2,3} so we cannot
    # recover information about buffer2 (it essentially doesn't exist anymore).
    buffer2_out = color.strip(gdb.execute("ng-slotu buffer2", to_string=True))
    if binary == HEAP_MALLOCNG_DYN:
        assert (
            "Could not load valid meta from local information, searching the heap.." in buffer2_out
        )
        assert "Found a slot with p @" in buffer2_out
        assert "doesn't seem to exist." in buffer2_out
        assert "Local memory:" in buffer2_out
    else:
        # The group got munmap()-ed.
        assert "not readable" in buffer2_out


@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
def test_mallocng_slot_start(start_binary, binary):
    start_binary(binary)

    gdb.execute("break break_here")

    gdb.execute("continue")
    gdb.execute("finish")

    # Check ng-slots is the same as ng-slotu when p == start
    # and that they aren't the same when p != start.

    slotu_buffer2_out = color.strip(gdb.execute("ng-slotu buffer2", to_string=True))
    slots_buffer2_out = color.strip(gdb.execute("ng-slots buffer2", to_string=True))
    slotu_buffer5_out = color.strip(gdb.execute("ng-slotu buffer5", to_string=True))
    slots_buffer5_out = color.strip(gdb.execute("ng-slots buffer5", to_string=True))

    assert "not cyclic" in slotu_buffer2_out
    assert slotu_buffer2_out == slots_buffer2_out

    if binary == HEAP_MALLOCNG_STATIC:
        assert "not cyclic" not in slotu_buffer5_out
        # Doing `ng-slots buffer5` will give you garbage since buffer5 is not
        # a valid slot start.
        assert slotu_buffer5_out != slots_buffer5_out
