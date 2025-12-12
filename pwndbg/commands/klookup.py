from __future__ import annotations

import argparse

import pwndbg.aglib.kernel.kallsyms
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Lookup kernel symbols")

parser.add_argument("symbol", type=str, nargs="?", help="Address or symbol name to lookup")
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
    for sym_name, sym_type, sym_addr in syms:
        print(message.success(f"{sym_addr:#x} {sym_type} {sym_name}"))

    if apply:
        path = pwndbg.commands.cymbol.create_blank_elf()
        if path is None:
            return
        try:
            # path is not None means lief is installed
            import lief

            symelf = lief.ELF.parse(path)
            for sym_name, sym_type, sym_addr in syms:
                symelf.add_symtab_symbol(symelf.export_symbol(sym_name, sym_addr))
            symelf.write(path)
            pwndbg.dbg.selected_inferior().add_symbol_file(path)
            print(message.success(f"Added {len(syms)} symbols"))
        except Exception as e:
            print(message.error(e))
