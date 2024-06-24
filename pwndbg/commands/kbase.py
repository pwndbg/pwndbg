from __future__ import annotations

import argparse

import gdb

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.gdblib.kernel
from pwndbg import config
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Finds the kernel virtual base address.")

parser.add_argument("-r", "--rebase", action="store_true", help="rebase loaded symbol file")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kbase(rebase=False) -> None:
    if config.kernel_vmmap == "none":
        print(M.error("kbase does not work when kernel-vmmap is set to none"))
        return

    base = pwndbg.gdblib.kernel.kbase()

    if base is None:
        print(M.error("Unable to locate the kernel base"))
        return

    print(M.success(f"Found virtual text base address: {hex(base)}"))

    if not rebase:
        return

    symbol_file = gdb.current_progspace().filename

    if symbol_file:
        gdb.execute("symbol-file")
        gdb.execute(f"add-symbol-file {symbol_file} {hex(base)}")
    else:
        print(M.error("No symbol file is currently loaded"))
