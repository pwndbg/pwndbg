from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

HEAP_JEMALLOC_EXTENT_INFO = get_binary("heap_jemalloc_extent_info.native.out")
HEAP_JEMALLOC_HEAP = get_binary("heap_jemalloc_heap.native.out")
# Relax address regex to accept different virtual address layouts (ASLR / jemalloc mappings).
# Old pattern assumed addresses starting with 0x7ffff and a limited digit count which fails on some hosts.
re_match_valid_address = r"0x[0-9a-fA-F]{6,16}"


@pwndbg_test
async def test_jemalloc_find_extent(ctrl: Controller) -> None:
    import pwndbg.aglib

    await launch_to(ctrl, HEAP_JEMALLOC_EXTENT_INFO, "break_here")
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    # run jemalloc extent_info command
    result = (await ctrl.execute_and_capture("jemalloc find-extent ptr")).splitlines()

    expected_output = [
        "Jemalloc find extent",
        "This command was tested only for jemalloc 5.3.0 and does not support lower versions",
        "",
        r"Pointer Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "",
        r"Allocated Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "Size: 0x1000",
        "Small class: True",
    ]

    expected_idx = 0
    for i in range(len(result)):
        if expected_idx == len(expected_output):
            break
        if re.match(expected_output[expected_idx], result[i]) is not None:
            expected_idx += 1
    assert expected_idx == len(expected_output)


@pwndbg_test
async def test_jemalloc_extent_info(ctrl: Controller) -> None:
    import pwndbg.aglib

    await launch_to(ctrl, HEAP_JEMALLOC_EXTENT_INFO, "break_here")
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    find_extent_results = (await ctrl.execute_and_capture("jemalloc find-extent ptr")).splitlines()
    extent_address = None
    for line in find_extent_results:
        if "Extent Address:" in line:
            extent_address = int(line.split(" ")[-1], 16)
    if extent_address is None:
        raise ValueError("Could not find extent address")
    # run jemalloc extent_info command
    result = (await ctrl.execute_and_capture(f"jemalloc extent-info {extent_address}")).splitlines()

    expected_output = [
        "Jemalloc extent info",
        "This command was tested only for jemalloc 5.3.0 and does not support lower versions",
        "",
        r"Allocated Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "Size: 0x1000",
        "Small class: True",
    ]

    expected_idx = 0
    for i in range(len(result)):
        if expected_idx == len(expected_output):
            break
        if re.match(expected_output[expected_idx], result[i]) is not None:
            expected_idx += 1
    assert expected_idx == len(expected_output)


@pwndbg_test
async def test_jemalloc_heap(ctrl: Controller) -> None:
    import pwndbg.aglib

    await launch_to(ctrl, HEAP_JEMALLOC_HEAP, "break_here")
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    # run jemalloc extent_info command
    result = (await ctrl.execute_and_capture("jemalloc heap")).splitlines()

    expected_output = [
        "Jemalloc heap",
        "This command was tested only for jemalloc 5.3.0 and does not support lower versions",
    ]

    # Extent sizes different depending on the system built (it would seem), so only check for the 0x8000 size,
    # since it seems consistent. The output of an extent implies the rest of the command is working
    expected_output += [
        "",
        "Allocated Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "Size: 0x8000",
        "Small class: False",
    ]

    expected_idx = 0
    for i in range(len(result)):
        if expected_idx == len(expected_output):
            break
        if re.match(expected_output[expected_idx], result[i]) is not None:
            expected_idx += 1
    assert expected_idx == len(expected_output)
