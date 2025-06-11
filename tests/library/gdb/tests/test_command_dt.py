from __future__ import annotations

import re

import gdb

import tests

HEAP_MALLOC_CHUNK = tests.binaries.get("heap_malloc_chunk.out")


def test_command_dt_works_with_address(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")

    tcache = gdb.execute("print tcache", to_string=True)

    tcache_addr = tcache.split()[-1]

    out = gdb.execute(f'dt "struct tcache_perthread_struct" {tcache_addr}', to_string=True)

    exp_regex = (
        "struct tcache_perthread_struct @ 0x[0-9a-f]+\n"
        "    0x[0-9a-f]+ \\+0x0000 counts               : \\{[0-9]+, [0-9]+ <repeats 63 times>\\}\n"
        "    0x[0-9a-f]+ \\+0x[0-9a-f]{4} entries              : \\{0x[0-9a-f]+, 0x[0-9a-f]+ <repeats 63 times>\\}\n"
    )
    assert re.match(exp_regex, out)


def test_command_dt_works_with_no_address(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")

    out = gdb.execute('dt "struct tcache_perthread_struct"', to_string=True)

    exp_regex = (
        "struct tcache_perthread_struct\n"
        "    \\+0x0000 counts               : uint16_t \\[64\\]\n"
        "    \\+0x[0-9a-f]{4} entries              : tcache_entry \\*\\[64\\]\n"
    )
    assert re.match(exp_regex, out)
