from __future__ import annotations

import argparse

import pwndbg.chain
import pwndbg.color as C
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Dumps the arguments of a va_list.")
parser.add_argument("addr", type=int, help="Address of the va_list")
parser.add_argument("count", type=int, nargs="?", default=8, help="Number of arguments to dump")


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def valist(addr: int, count: int) -> None:
    # The `va_list` struct looks like this:
    #
    # ```
    # typedef struct {
    #    unsigned int gp_offset;
    #    unsigned int fp_offset;
    #    void *overflow_arg_area;
    #    void *reg_save_area;
    # } va_list[1];
    # ```

    gp_offset = pwndbg.aglib.memory.u32(addr)
    gp_index = gp_offset / 8

    overflow_arg_area = pwndbg.aglib.memory.u64(addr + 8)
    reg_save_area = pwndbg.aglib.memory.u64(addr + 16)

    indent = " " * len("gp_offset => ")
    print(f"{C.blue('reg_save_area')}")
    for i in range(6):
        line = ""
        if i == gp_index:
            line += "gp_offset => "
        else:
            line += indent

        line += pwndbg.chain.format(reg_save_area + i * 8)
        print(line)

    print()
    print(f"{C.blue('overflow_arg_area')}")
    for i in range(count - 6):
        print(indent + pwndbg.chain.format(overflow_arg_area + i * 8))
