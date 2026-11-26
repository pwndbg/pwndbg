from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.commands
from pwndbg import config
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Finds the kernel virtual base address.")

parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="show more information relevant to the kbase (e.g. phys addr)",
)


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kbase(verbose=False) -> None:
    if config.kernel_vmmap == "none":
        print(message.error("kbase does not work when kernel-vmmap is set to none"))
        return

    base = pwndbg.aglib.kernel.paging.kbase

    if base is None:
        print(message.error("Unable to locate the kernel base"))
        return

    print(message.success(f"Found virtual text base address: {hex(base)}"))

    if verbose:
        phys = pwndbg.aglib.kernel.paging.virt_to_phys(base)
        print(message.success(f"corresponding physical address: {hex(phys)}"))

    pwndbg.aglib.kernel.rebase_symbols()
