from __future__ import annotations

import argparse

import gdb

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.gdblib.kernel
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.vmmap
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.config import config

parser = argparse.ArgumentParser(description="Finds the kernel virtual base address.")

parser.add_argument("-r", "--rebase", metavar="vmlinux", type=str, help="specify the vmlinux file")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kbase(rebase) -> None:
    if config.kernel_vmmap == "none":
        print(M.error("kbase does not work when kernel-vmmap is set to none"))
        return

    print(M.success(f"Found virtual text base address: {hex(pwndbg.gdblib.kernel.kbase())}"))

    if rebase:
        gdb.execute(f"add-symbol-file {rebase} {hex(pwndbg.gdblib.kernel.kbase())}")
