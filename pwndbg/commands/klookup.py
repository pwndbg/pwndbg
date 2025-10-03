from __future__ import annotations

import argparse

import lief

import pwndbg.aglib.kernel.kallsyms
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Lookup kernel symbols")

parser.add_argument("symbol", type=str, nargs="?", help="Address or symbol name to lookup")
parser.add_argument(
    "-a", "--apply", action="store_true", help="applies all the symbols that satisfy the filter"
)


@pwndbg.commands.Command(parser, aliases=["kallsyms", "ks"], category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def klookup(symbol: str, apply: bool) -> None:
    ksyms = pwndbg.aglib.kernel.kallsyms.get()
    syms = []
    try:
        symbol_addr = int(symbol, 0)
        for ksym, v in ksyms.items():
            if v[0] == symbol_addr:
                syms.append((ksym, v[0], v[1]))
        if len(syms) == 0:
            print(message.error(f"No symbol found at {symbol_addr:#x}"))
    except (ValueError, TypeError):
        for ksym, v in ksyms.items():
            if symbol is not None and symbol not in ksym:
                continue
            syms.append((ksym, v[0], v[1]))
        if len(syms) == 0:
            print(message.error(f"No symbol found for {symbol}"))
    for sym_name, sym_addr, sym_type in syms:
        print(message.success(f"{sym_addr:#x} {sym_type} {sym_name}"))
    if apply:
        path = pwndbg.commands.cymbol.create_blank_elf()
        symelf = lief.ELF.parse(path)
        for sym_name, sym_addr, sym_type in syms:
            symelf.add_symtab_symbol((symelf.export_symbol(sym_name, sym_addr)))
        symelf.write(path)
        pwndbg.dbg.selected_inferior().add_symbol_file(path)
