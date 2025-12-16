from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg import config
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Finds the kernel virtual base address.")

parser.add_argument("-r", "--rebase", action="store_true", help="rebase loaded symbol file")
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="show more information relevant to the kbase (e.g. phys addr)",
)


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kbase(rebase=False, verbose=False) -> None:
    if config.kernel_vmmap == "none":
        print(M.error("kbase does not work when kernel-vmmap is set to none"))
        return

    base = pwndbg.aglib.kernel.arch_paginginfo().kbase

    if base is None:
        print(M.error("Unable to locate the kernel base"))
        return

    print(M.success(f"Found virtual text base address: {hex(base)}"))

    if verbose:
        phys = pwndbg.aglib.kernel.virt_to_phys(base)
        if phys is not None:
            print(M.success(f"corresponding physical address: {hex(phys)}"))

    if not rebase:
        return

    symbol_file = pwndbg.aglib.proc.exe()

    if symbol_file:
        pwndbg.dbg.selected_inferior().add_symbol_file(symbol_file, base)
    else:
        print(M.error("No symbol file is currently loaded"))
