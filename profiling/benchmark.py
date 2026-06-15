from __future__ import annotations

import argparse
import cProfile
import pstats
import time
from collections.abc import Callable

import gdb

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.vmmap
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.lib.cache

COUNT = 100


def run_benchmark(
    name: str, prefix: str, callback: Callable, count: int = COUNT, with_cache: bool = True
) -> float:
    """
    Return:
        Average time to execute callback in seconds
    """
    profiler = cProfile.Profile()

    profiler.enable()

    for _ in range(count):
        if not with_cache:
            pwndbg.lib.cache.clear_caches()
        callback()

    profiler.disable()

    pstats_file_name_base = f"{prefix}-{count}-{name}-{int(time.time())}"
    filename = f"{pstats_file_name_base}.pstats"
    profiler.dump_stats(filename)

    full_time = pstats.Stats(profiler).total_tt

    print(f"Time elapsed: {full_time}. Average time: {full_time / count}")
    print(f"Saved benchmark data to {filename}")

    return full_time / count


parser = argparse.ArgumentParser(
    description="""
Benchmark contexts.

Uses cProfile to instrument the code.

Experimentally, this can cause the code to run ~2.5 times slower than it's real speed.
However, you can use it to find relative performance before/after changes, and find functions that take longer than they should.
""",
)

parser.add_argument("name", type=str, help="Name placed into output pstats filename")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.DEV)
def benchmark_context(name: str):
    # Context - clear cache
    ## Benchmark the `context` command, no caching

    def run_with_clear():
        pwndbg.lib.cache.clear_caches()
        pwndbg.commands.context.context.function()

    run_benchmark(name, "context-without-cache", run_with_clear)

    pwndbg.lib.cache.clear_caches()

    # Context - with cache
    ## Benchmark the `context` command with cache
    run_benchmark(
        name,
        "context-with-cache",
        # Bypass the decorator so cProfile/snakeviz sees things correctly
        lambda: pwndbg.commands.context.context.function(),
    )

    pwndbg.lib.cache.clear_caches()

    # Step

    def run_with_step():
        gdb.execute("stepi")
        # Bypass the decorator so cProfile can see function stack correctly
        pwndbg.commands.context.context.function()

    run_benchmark(name, "step", run_with_step)

    # Regs

    def regs():
        gdb.execute("stepi")
        pwndbg.commands.context.context_regs()

    run_benchmark(name, "regs", regs)

    # Disasm

    def disasm():
        gdb.execute("stepi")
        pwndbg.commands.context.context_disasm()

    run_benchmark(name, "disasm", disasm)

    # Stack

    def stack():
        gdb.execute("stepi")
        pwndbg.commands.context.context_stack()

    run_benchmark(name, "stack", stack)


parser = argparse.ArgumentParser(
    description="""
Benchmark telescoping the entire stack
    """,
)
parser.add_argument("name", type=str, help="Name placed into output pstats filename")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.DEV)
def benchmark_large_telescope(name: str):
    # Telescope entire stack
    stack_page = pwndbg.aglib.vmmap.find(pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.stack))
    start = stack_page.start
    len = stack_page.memsz

    def print_all_stack():
        pwndbg.commands.telescope.telescope(start, len // pwndbg.aglib.arch.ptrsize)

    run_benchmark(name, "all-stack", print_all_stack, 4)
