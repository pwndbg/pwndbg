from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

HEAP_MALLOC_CHUNK = get_binary("heap_malloc_chunk.native.out")


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
        "    0x[0-9a-f]+ \\+0x0000 (counts|num_slots) +: +.*\\{((0x[0-9a-f]+|[0-9]+), (0x[0-9a-f]+|[0-9]+) <repeats (63|75) times>|(\\s*\\[[0-9]+\\] = [0-9]){20,76}\\s*([.]+\\s*)?)\\}\n"
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
