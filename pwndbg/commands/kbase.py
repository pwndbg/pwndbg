from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.dbg
from pwndbg import config
from pwndbg.commands import CommandCategory

if pwndbg.dbg.is_gdblib_available():
    import gdb


parser = argparse.ArgumentParser(description="Finds the kernel virtual base address.")

parser.add_argument("-r", "--rebase", action="store_true", help="rebase loaded symbol file")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kbase(rebase=False) -> None:
    if config.kernel_vmmap == "none":
        print(M.error("kbase does not work when kernel-vmmap is set to none"))
        return

    base = pwndbg.aglib.kernel.kbase()

    if base is None:
        print(M.error("Unable to locate the kernel base"))
        return

    print(M.success(f"Found virtual text base address: {hex(base)}"))

    if not rebase:
        return

    symbol_file = pwndbg.dbg.selected_inferior().main_module_name()

    if symbol_file:
        if pwndbg.dbg.is_gdblib_available():
            gdb.execute("symbol-file")
            gdb.execute(f"add-symbol-file {symbol_file} {hex(base)}")
        else:
            print(M.error("Adding symbol not supported in LLDB yet"))
    else:
        print(M.error("No symbol file is currently loaded"))
