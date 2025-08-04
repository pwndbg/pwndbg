"""
Displays the syscall table for kernel debugging.
"""

from __future__ import annotations

import argparse

import pwndbg.color.message as message
import pwndbg.commands

parser = argparse.ArgumentParser(
    description="Displays Linux syscall table, including names and addresses of syscalls."
)

parser.add_argument("syscall_name", nargs="?", type=str, help="A syscall name to search for")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugSymbols
def ksyscalls(syscall_name=None) -> None:
    # Look up the address of the sys_call_table symbol.
    table_addr = pwndbg.aglib.symbol.lookup_symbol_addr("sys_call_table")
    if table_addr is None:
        print(
            "The sys_call_table symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return

    try:
        # Compute number of syscalls in the table.
        sc_count = int(
            pwndbg.dbg.selected_frame().evaluate_expression(
                "sizeof(sys_call_table) / sizeof(void *)"
            )
        )
    except pwndbg.dbg_mod.Error:
        print(
            "The sys_call_table symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return

    try:
        print(f"Syscall table address with {sc_count} entries found at {table_addr:#x}.\n")

        size_ptr = pwndbg.aglib.arch.ptrsize

        print(f"{'':>4} {'Address':>18} {'Symbol'}")

        # Iterate through the syscall table entries.

        for i in range(sc_count):
            sc_addr = pwndbg.aglib.memory.read_pointer_width(table_addr + i * size_ptr)

            symbol = pwndbg.aglib.symbol.resolve_addr(sc_addr)

            if syscall_name is not None:
                if symbol is None or syscall_name not in symbol:
                    continue

            print_entry = lambda: print(f"{i:>4} {hex(sc_addr):>18} {symbol or '<unknown>'}")
            print_entry()

    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return
