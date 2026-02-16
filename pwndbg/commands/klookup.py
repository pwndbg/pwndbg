from __future__ import annotations

import argparse
import os
import tempfile

import niche_elf
import niche_elf.datatypes

import pwndbg
import pwndbg.aglib.kernel.kallsyms
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Lookup kernel symbols")

parser.add_argument(
    "symbol", type=str, nargs="?", default="", help="Address or symbol name to lookup"
)
parser.add_argument(
    "-a", "--apply", action="store_true", help="applies all the symbols that satisfy the filter"
)


@pwndbg.commands.Command(
    parser,
    aliases=["kallsyms", "ks"],
    category=CommandCategory.KERNEL,
    notes="""
Using `--apply` makes sense for kernel modules. If you want to symbolize the whole kernel,
use vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf) or compile it yourself.
""",
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def klookup(symbol: str, apply: bool) -> None:
    ksyms = pwndbg.aglib.kernel.kallsyms.get()
    syms = []
    try:
        symbol_addr = int(symbol, 0)
        for sym in ksyms:
            if sym[2] == symbol_addr:
                syms.append(sym)
        if len(syms) == 0:
            print(message.error(f"No symbol found at {symbol_addr:#x}"))
    except (ValueError, TypeError):
        for sym in ksyms:
            if symbol is None or symbol in sym[0]:
                syms.append(sym)
        if len(syms) == 0:
            print(message.error(f"No symbol found for {symbol}"))

    if not (apply and symbol == ""):
        for sym_name, sym_type, sym_addr in syms:
            print(message.success(f"{sym_addr:#x} {sym_type} {sym_name}"))

    if apply:
        if pwndbg.dbg.name() == pwndbg.dbg_mod.DebuggerType.LLDB:
            print(message.error("Symbolication is not yet supported on LLDB."))
            # Until we implement add_symbol_file for LLDB.
            return

        base: int | None = pwndbg.aglib.kernel.kbase()

        if base is None:
            # I would be suprised if this was actually possible, we managed to find kallsyms but not
            # kbase?
            # But anyway, passing 0 to ELFFile and no ADDR argument to add_symbol_file should still work.
            elf: niche_elf.ELFFile = niche_elf.ELFFile(0)
        else:
            elf = niche_elf.ELFFile(base)

        for sym_name, sym_type, sym_addr in syms:
            # I trust bata: bata24/gef.py:create_symboled_elf()
            if sym_type and sym_type in "abcdefghijklmnopqrstuvwxyz":
                bind: int = niche_elf.datatypes.Constants.STB_LOCAL
            else:
                bind = niche_elf.datatypes.Constants.STB_GLOBAL

            if sym_type in ["T", "t", "W", None]:
                elf.add_function(sym_name, sym_addr, bind=bind)
            else:
                elf.add_object(sym_name, sym_addr, bind=bind)

        _, elf_path = tempfile.mkstemp(prefix="ks-symbols-", suffix=".elf")
        elf.write(elf_path)

        pwndbg.dbg.selected_inferior().add_symbol_file(elf_path, base)

        print(message.success(f"Added {len(syms)} symbols"))

        # Delete the file after GDB closes its file descriptor.
        os.unlink(elf_path)
        return
