from __future__ import annotations

import argparse

import pwndbg.aglib.kernel.kallsyms
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Lookup kernel symbols")

parser.add_argument("symbol", type=str, help="Address or symbol name to lookup")


def parse_to_addr(v: str) -> int:
    if v.startswith("0x"):
        return int(v[2:], 16)
    try:
        return int(v, 16)
    except ValueError:
        # fallback base 10
        return int(v, 10)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def klookup(symbol: str) -> None:
    ksyms = pwndbg.aglib.kernel.kallsyms.get()
    try:
        symbol_addr = parse_to_addr(symbol)
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
