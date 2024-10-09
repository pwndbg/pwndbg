from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.gdblib.kernel.kallsyms
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Lookup kernel symbols")

parser.add_argument("symbol", type=str, help="Address or symbol name to lookup")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def klookup(symbol: str) -> None:
    ksyms = pwndbg.gdblib.kernel.kallsyms.get()
    try:
        symbol_addr = int(symbol)
        for k, v in ksyms.items():
            if v[0] == symbol_addr:
                print(message.success(f"{k} = {symbol_addr:#x}"))
                return
        print(message.error(f"No symbol found at {symbol_addr:#x}"))
    except ValueError:
        if symbol in ksyms:
            addr = ksyms[symbol][0]
            print(message.success(f"{symbol} = {addr:#x}"))
        else:
            print(message.error(f"No symbol found for {symbol}"))
