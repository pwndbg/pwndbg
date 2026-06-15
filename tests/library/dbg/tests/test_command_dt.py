from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

HEAP_MALLOC_CHUNK = get_binary("heap_malloc_chunk.native.out")
DT_RECURSIVE_OFFSETS = get_binary("dt_recursive_offsets.native.out")
DT_BITFIELDS = get_binary("dt_bitfields.native.out")


@pwndbg_test
async def test_command_dt_works_with_address(ctrl: Controller) -> None:
    import pwndbg.aglib

    await launch_to(ctrl, HEAP_MALLOC_CHUNK, "break_here")

    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    tcache = await ctrl.execute_and_capture("print tcache")

    tcache_addr = tcache.split()[-1]

    out = await ctrl.execute_and_capture(f'dt "struct tcache_perthread_struct" {tcache_addr}')

    # Accounting for differences between architectures and glibc versions (specifically 2.42)
    exp_regex = (
        "struct tcache_perthread_struct @ 0x[0-9a-f]+\n"
        "    0x[0-9a-f]+ \\+0x0000 (counts|num_slots) +: +.*\\{((0x[0-9a-f]+|[0-9]+), (0x[0-9a-f]+|[0-9]+) <repeats (63|75) times>|(\\s*\\[[0-9]+\\] = [0-9]+){20,76}\\s*([.]+\\s*)?)\\}\n"
        "    0x[0-9a-f]+ \\+0x[0-9a-f]{4} entries +: +.*\\{(0x[0-9a-f]+, 0x[0-9a-f]+ <repeats (63|75) times>|(\\s*\\[[0-9]+\\] = (0x[0-9a-f]+|NULL)){20,76}\\s*([.]+\\s*)?)\\}"
    )
    assert re.match(exp_regex, out)


@pwndbg_test
async def test_command_dt_works_with_no_address(ctrl: Controller) -> None:
    import pwndbg.aglib

    await launch_to(ctrl, HEAP_MALLOC_CHUNK, "break_here")

    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    out = await ctrl.execute_and_capture('dt "struct tcache_perthread_struct"')

    exp_regex = (
        "struct tcache_perthread_struct\n"
        "    \\+0x0000 (counts|num_slots) +: +uint16_t ?\\[(64|76)\\]\n"
        "    \\+0x[0-9a-f]{4} entries +: +tcache_entry ?\\*\\[(64|76)\\]\n"
    )
    assert re.match(exp_regex, out)


@pwndbg_test
async def test_command_dt_recursively_prints_nested_offsets(ctrl: Controller) -> None:
    await launch_to(ctrl, DT_RECURSIVE_OFFSETS, "break_here")

    global_outer = await ctrl.execute_and_capture("print &global_outer")
    match = re.search(r"0x[0-9a-f]+", global_outer)
    assert match is not None
    global_outer_addr = match.group(0)

    out = await ctrl.execute_and_capture(f'dt "struct dt3807_outer" {global_outer_addr}')

    assert re.search(r"\+0x0000 x\s+: 0x11", out)
    assert re.search(r"\+0x0004 in\s+: dt3807_inner \{", out)
    assert re.search(r"\+0x0004 a\s+: 0x22", out)
    assert re.search(r"\+0x0008 b\s+: 0x33", out)
    assert re.search(r"\+0x000c y\s+: 0x44", out)


@pwndbg_test
async def test_command_dt_bitfield_alignment(ctrl: Controller) -> None:
    await launch_to(ctrl, DT_BITFIELDS, "break_here")

    global_bf = await ctrl.execute_and_capture("print &global_bf")
    match = re.search(r"0x[0-9a-f]+", global_bf)
    assert match is not None
    global_bf_addr = match.group(0)

    out = await ctrl.execute_and_capture(f'dt "struct dt3076_bitfields" {global_bf_addr}')

    # All ": " separators should be at the same column (bitfields don't break alignment)
    lines = [line for line in out.splitlines() if " : " in line]
    assert len(lines) >= 4
    colon_positions = [line.index(" : ") for line in lines]
    assert len(set(colon_positions)) == 1, f"Misaligned colons in:\n{out}"
