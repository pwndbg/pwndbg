from __future__ import annotations

import argparse

import pwndbg.aglib.kernel.kallsyms
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Lookup kernel symbols")

parser.add_argument("symbol", type=str, help="Address or symbol name to lookup")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def klookup(symbol: str) -> None:
    ksyms = pwndbg.aglib.kernel.kallsyms.get()
    try:
        symbol_addr = int(symbol, 0)
        for ksym, v in ksyms.items():
            if v[0] == symbol_addr:
                print(message.success(f"{symbol_addr:#x} = {ksym}"))
                return
        print(message.error(f"No symbol found at {symbol_addr:#x}"))
    except ValueError:
        found = False
        for ksym, v in ksyms.items():
            if symbol not in ksym:
                continue
            found = True
            addr = v[0]
            print(message.success(f"{addr:#x} = {ksym}"))
        if not found:
            print(message.error(f"No symbol found for {symbol}"))
