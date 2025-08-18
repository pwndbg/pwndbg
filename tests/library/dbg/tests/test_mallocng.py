from __future__ import annotations

import re
from typing import List

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

HEAP_MALLOCNG_DYN = get_binary("heap_musl_dyn.out")
HEAP_MALLOCNG_STATIC = get_binary("heap_musl_static.out")

# Userland only
re_addr = r"0x[0-9a-fA-F]{1,12}"


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_slot_user(ctrl: Controller, binary: str):
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")
    # Get out of the break_here() function.
    await ctrl.finish()

    # == Check generic command output ==

    buffer1_out = (await ctrl.execute_and_capture("ng-slotu buffer1")).splitlines()

    # Strip the colors. FIXME: After #3142 is figured out.
    buffer1_out = [color.strip(x) for x in buffer1_out]

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
        "  state:          allocated         ",
        "in-band",
        r"  offset:         0x[0-9] \(0x[0-9]{0,1}0\)         distance to first slot start \/ 0x10",
        r"  index:          0x0               index of slot in its group",
        "  hdr reserved:   0x5               describes: end - p - n",
        "                                    use ftr reserved",
        "  ftr reserved:   0xc               ",
        r"  cyclic offset:  NA \(not cyclic\)   prevents double free, \(p - start\) / 0x10",
    ]

    assert len(expected_output) == len(buffer1_out)

    for i in range(len(expected_output)):
        assert re.match(expected_output[i], buffer1_out[i])

    # == Check various fields ==
    buffer2_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer2")).splitlines()
    buffer4_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer4")).splitlines()

    stride_idx = 7
    user_size_idx = 8
    slack_idx = 9
    state_idx = 10
    offset_idx = 12
    index_idx = 13
    hdr_res_idx = 14
    ftr_res_idx = 16
    cyclic_idx = 17

    # Check stride
    assert "stride" in buffer2_out[stride_idx] and " 0x30 " in buffer2_out[stride_idx]
    assert "stride" in buffer4_out[stride_idx] and " 0x2a0 " in buffer4_out[stride_idx]

    # Check user size
    assert "user size" in buffer2_out[user_size_idx] and " 0x20 " in buffer2_out[user_size_idx]
    assert "user size" in buffer4_out[user_size_idx] and " 0x211 " in buffer4_out[user_size_idx]

    # Check slack
    assert "slack" in buffer2_out[slack_idx] and " 0x0 " in buffer2_out[slack_idx]
    assert "slack" in buffer4_out[slack_idx] and " 0x8 (0x80) " in buffer4_out[slack_idx]

    # Check allocation status
    assert "state" in buffer2_out[state_idx] and " allocated " in buffer2_out[state_idx]
    assert "state" in buffer4_out[state_idx] and " allocated " in buffer4_out[state_idx]

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

    # == Check command on free slots ==
    break_at_sym("break_here")
    await ctrl.cont()
    await ctrl.cont()
    await ctrl.finish()

    buffer2_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer2"))

    # Make sure we found the thingy even though it is invalid locally.
    assert (
        "Could not load valid meta from local"
        " information, searching the heap.. Found it." in buffer2_out
    )
    assert "Local slot memory:" in buffer2_out
    assert "Slot information from the group/meta:" in buffer2_out

    # Check we correctly detected slot state
    assert "state:          freed" in buffer2_out

    await ctrl.cont()
    await ctrl.finish()

    # Now buffer3 got free()'d and so did the group which contained buffer{1,2,3} so we cannot
    # recover information about buffer2 (it essentially doesn't exist anymore).
    buffer2_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer2"))
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


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_slot_start(ctrl: Controller, binary: str):
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")
    await ctrl.finish()

    # Check ng-slots is the same as ng-slotu when p == start
    # and that they aren't the same when p != start.

    slotu_buffer2_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer2"))
    slots_buffer2_out = color.strip(await ctrl.execute_and_capture("ng-slots buffer2"))
    slotu_buffer5_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer5"))
    slots_buffer5_out = color.strip(await ctrl.execute_and_capture("ng-slots buffer5"))

    assert "not cyclic" in slotu_buffer2_out
    assert slotu_buffer2_out == slots_buffer2_out

    if binary == HEAP_MALLOCNG_STATIC:
        assert "not cyclic" not in slotu_buffer5_out
        # Doing `ng-slots buffer5` will give you garbage since buffer5 is not
        # a valid slot start.
        assert slotu_buffer5_out != slots_buffer5_out


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_group(ctrl: Controller, binary: str):
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")
    await ctrl.finish()

    # Fetch the group where buffer1 is in.

    buffer1_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer1"))
    group_addr = int(re.search(r"group:\s*(0x[0-9a-fA-F]+)", buffer1_out).group(1), 16)

    # == Check command output looks good.

    group1_out = color.strip(await ctrl.execute_and_capture(f"ng-group {group_addr}")).splitlines()

    expected_out = [
        "group",
        f"  @ {re_addr} - {re_addr}",
        f"  meta:           {re_addr}    ",
        "  active_idx:     0x9               ",
        f"  storage:        {re_addr}    start of slots",
        "---",
        "  group size:     0x1f0             ",
        "meta",
        f"  @ {re_addr}",
        f"  prev:           {re_addr}    ",
        f"  next:           {re_addr}    ",
        f"  mem:            {re_addr}    the group",
        "  avail_mask:     0x3f8             0b00000000000000000000001111111000",
        "  freed_mask:     0x0               0b00000000000000000000000000000000",
        r"  last_idx:       0x9 \(cnt: 0xa\)    index of last slot",
        "  freeable:       True              ",
        r"  sizeclass:      0x2 \(stride: 0x30\)  ",
        "  maplen:         0x0               ",
        "",
        rf"Group nested in slot of another group \({re_addr}\).",
        "",
        "Slot statuses: UUUAAAAAAA",
        r"  \(U: Inuse \(allocated\) / F: Freed / A: Available\)",
    ]

    assert len(expected_out) == len(group1_out)

    for i in range(len(expected_out)):
        assert re.match(expected_out[i], group1_out[i])

    # == Check group traversal is done properly.
    pgline_idx = -4

    assert "another group" in group1_out[pgline_idx]

    # We are going to fetch parent groups recursively until
    # we reach the outermost group which is either mmap()-ed in or
    # has donated by ld.
    cur_group_out: List[str] = group1_out
    cur_group_addr: int = group_addr

    while "another group" in cur_group_out[pgline_idx]:
        cur_group_addr = int(
            re.search(r"group \((0x[0-9a-fA-F]+)\)", cur_group_out[pgline_idx]).group(1), 16
        )
        cur_group_out = color.strip(
            await ctrl.execute_and_capture(f"ng-group {cur_group_addr}")
        ).splitlines()

    if binary == HEAP_MALLOCNG_STATIC:
        assert "mmap()" in cur_group_out[pgline_idx]
    else:
        assert "donated by ld" in cur_group_out[pgline_idx]


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_meta(ctrl: Controller, binary: str):
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")
    await ctrl.finish()

    buffer1_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer1"))
    meta_addr = int(re.search(r"meta:\s*(0x[0-9a-fA-F]+)", buffer1_out).group(1), 16)
    group_addr = int(re.search(r"group:\s*(0x[0-9a-fA-F]+)", buffer1_out).group(1), 16)

    # Check that the meta output is the same as the group output.
    # They both print the same group and meta objects.
    meta_out = color.strip(await ctrl.execute_and_capture(f"ng-meta {meta_addr}"))
    group_out = color.strip(await ctrl.execute_and_capture(f"ng-group {group_addr}"))

    assert meta_out == group_out


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_malloc_context(ctrl: Controller, binary: str):
    import pwndbg.color as color

    await ctrl.launch(binary)

    # Check that we do not find it at the first program instruction
    if binary == HEAP_MALLOCNG_DYN:
        # Since our static binary is symbolicated, we would still find
        # __malloc_context by simply looking up the symbol. So we only
        # check this for the dynamically linked binary.

        # This is at _dlstart - the heap is uninitialized at this point.
        ctx_out = color.strip(await ctrl.execute_and_capture("ng-ctx"))

        assert "Couldn't find" in ctx_out
        assert "will not work" in ctx_out
        assert "aborting" in ctx_out

    # == Check that we do find it at program entry
    await ctrl.execute("entry")
    # This is at _start. For a dynamically linked binary ld performed memory
    # donation so the heap should be initialized at this point.
    # For a statically linked binary, this won't happen but we will have access
    # to the __malloc_context symbol.
    # If we were testing on a stripped static binary this would fail as the
    # heap would only get initialized after the first malloc() in main.
    ctx_out = color.strip(await ctrl.execute_and_capture("ng-ctx"))
    assert "Couldn't find" not in ctx_out
    assert "will not work" not in ctx_out
    assert "aborting" not in ctx_out

    assert "ctx\n" in ctx_out
    assert "init_done:" in ctx_out


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_find(ctrl: Controller, binary: str):
    import pwndbg
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")
    await ctrl.finish()

    # Check no slot found
    find_out = color.strip(await ctrl.execute_and_capture("ng-find $rip"))
    assert "No slot found containing that address.\n" == find_out

    buffer1_addr = int(pwndbg.dbg.selected_frame().evaluate_expression("buffer1"))

    # Check we find the slot in the simplest case of providing p.
    find_out = color.strip(await ctrl.execute_and_capture("ng-find buffer1"))

    assert "No slot found" not in find_out
    start_addr = int(re.search(r"start:\s*(0x[0-9a-fA-F]+)", find_out).group(1), 16)
    user_addr = int(re.search(r"user start:\s*(0x[0-9a-fA-F]+)", find_out).group(1), 16)
    assert buffer1_addr == start_addr == user_addr

    group_addr = int(re.search(r"group:\s*(0x[0-9a-fA-F]+)", find_out).group(1), 16)

    # Hit the buffer1 header metadata
    find_out = color.strip(await ctrl.execute_and_capture("ng-find buffer1-1"))

    # We should hit the slot that holds buffer1's group.
    hit_start_addr = int(re.search(r"start:\s*(0x[0-9a-fA-F]+)", find_out).group(1), 16)
    assert group_addr == hit_start_addr

    # Hit the buffer1 header metadata but with -m
    find_out = color.strip(await ctrl.execute_and_capture("ng-find buffer1-1 --metadata"))

    # We should hit the buffer1 slot
    hit_start_addr = int(re.search(r"start:\s*(0x[0-9a-fA-F]+)", find_out).group(1), 16)
    assert buffer1_addr == hit_start_addr

    # Check that `--shallow` works. Note that `--all` prints the group allocation method.
    find_out = color.strip(await ctrl.execute_and_capture("ng-find buffer1 --shallow --all"))
    assert "donated by ld" in find_out or "mmap" in find_out
    assert "nested" not in find_out.splitlines()[-1]


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_metaarea(ctrl: Controller, binary: str):
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")
    await ctrl.finish()

    context = color.strip(await ctrl.execute_and_capture("ng-ctx"))
    secret = int(re.search(r"secret:\s*(0x[0-9a-fA-F]+)", context).group(1), 16)
    meta_area_addr = int(re.search(r"meta_area_head:\s*(0x[0-9a-fA-F]+)", context).group(1), 16)

    meta_area_out = color.strip(
        await ctrl.execute_and_capture(f"ng-metaarea {meta_area_addr:#x}")
    ).splitlines()

    expected_out = [
        "meta_area",
        f"  @ {meta_area_addr:#x} - {re_addr}",
        f"  check:          {secret:#x}",
        "  next:           0",
        r"  nslots:         0x[0-9a-f]{2}",
        f"  slots:          {re_addr}    ",
    ]

    assert len(expected_out) == len(meta_area_out)

    for i in range(len(expected_out)):
        assert re.match(expected_out[i], meta_area_out[i])


@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_vis(ctrl: Controller, binary: str):
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")

    break_at_sym("break_here")
    await ctrl.cont()
    await ctrl.cont()
    await ctrl.finish()

    vis_out = color.strip(await ctrl.execute_and_capture("ng-vis buffer1")).splitlines()

    expected_out = [
        f"group @ {re_addr}",
        f"meta @ {re_addr}",
        "LEGEND: .*",
        "LEGEND: .*",
        "",
        rf"{re_addr}0\t0x[0-9a-fA-F]{{16}}\t0x0000ff0000000009\t................",
        rf"{re_addr}0\t0x0a0a0a0a0a0a0a0a\t0x0a0a0a0a0a0a0a0a\t................",
        rf"{re_addr}0\t0x0a0a0a0a0a0a0a0a\t0x0a0a0a0a0a0a0a0a\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000ff000000000c\t................",
        rf"{re_addr}0\t0x0b0b0b0b0b0b0b0b\t0x0b0b0b0b0b0b0b0b\t................",
        rf"{re_addr}0\t0x0b0b0b0b0b0b0b0b\t0x0b0b0b0b0b0b0b0b\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0006a2000000000c\t................   2 \+ \(5 << 5\)",
        rf"{re_addr}0\t0x0c0c0c0c0c0c0c0c\t0x0c0c0c0c0c0c0c0c\t................",
        rf"{re_addr}0\t0x0c0c0c0c0c0c0c0c\t0x0c0c0c0c0c0c0c0c\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x000000000000000c\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
        rf"{re_addr}0\t0x0000000000000000\t0x0000000000000000\t................",
    ]

    assert len(expected_out) == len(vis_out)

    for i in range(len(expected_out)):
        assert re.match(expected_out[i], vis_out[i])

    # Make sure ng-vis properly resolves anywhere inside the slot.
    # The stride of the group is 0x30.
    vis_out2 = color.strip(await ctrl.execute_and_capture("ng-vis buffer1+0x2F")).splitlines()
    assert vis_out == vis_out2

    # Step over the free(buffer3)
    await ctrl.execute("next")
    # Check that the output is not the same anymore since the group got freed.
    # (Now the outer group will be printed.)
    vis_out3 = color.strip(await ctrl.execute_and_capture("ng-vis buffer1")).splitlines()
    assert len(vis_out3) > len(vis_out)
