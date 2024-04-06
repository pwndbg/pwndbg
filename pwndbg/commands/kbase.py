from __future__ import annotations

import argparse

import gdb

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.gdblib.kernel
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.config import config

parser = argparse.ArgumentParser(description="Finds the kernel virtual base address.")

parser.add_argument("-r", "--rebase", action="store_true", help="rebase loaded symbol file")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kbase(rebase=None) -> None:
    if config.kernel_vmmap == "none":
        print(M.error("kbase does not work when kernel-vmmap is set to none"))
        return

    print(M.success(f"Found virtual text base address: {hex(pwndbg.gdblib.kernel.kbase())}"))

    if not rebase:
        return

    symbol_file = gdb.current_progspace().filename

    if symbol_file:
        gdb.execute("file", to_string=True)
        gdb.execute(f"add-symbol-file {symbol_file} {hex(pwndbg.gdblib.kernel.kbase())}")
    else:
        print(M.error("No symbol file is currently loaded"))
