from __future__ import annotations

import re

import gdb

import tests

HEAP_MALLOC_CHUNK = tests.get_binary("heap_malloc_chunk.out")


def test_command_dt_works_with_address(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")

    tcache = gdb.execute("print tcache", to_string=True)

    tcache_addr = tcache.split()[-1]

    out = gdb.execute(f'dt "struct tcache_perthread_struct" {tcache_addr}', to_string=True)

    exp_regex = (
        r"struct tcache_perthread_struct @ 0x[0-9a-f]+\n"
        r"\s+0x[0-9a-f]+\s+\+0x0000\s+counts\s*:\s*\{[0-9]+, [0-9]+ <repeats 63 times>\}\n"
        r"\s+0x[0-9a-f]+\s+\+0x[0-9a-f]{4}\s+entries\s*:\s*\{0x[0-9a-f]+, 0x[0-9a-f]+ <repeats 63 times>\}"
    )
    assert re.search(exp_regex, out), f"Output:\n{out}\n\nDid not match regex:\n{exp_regex}"


def test_command_dt_works_with_no_address(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")

    out = gdb.execute('dt "struct tcache_perthread_struct"', to_string=True)

    exp_regex = (
        r"struct tcache_perthread_struct\n"
        r"\s+\+0x0000\s+counts\s*:\s*uint16_t\s*\[64\]\n"
        r"\s+\+0x[0-9a-f]{4}\s+entries\s*:\s*tcache_entry\s*\*\[64\]"
    )
    assert re.search(exp_regex, out), f"Output:\n{out}\n\nDid not match regex:\n{exp_regex}"
