from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.gdblib.kernel
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Outputs the kernel version (/proc/version).")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kversion() -> None:
    print(pwndbg.gdblib.kernel.kversion())
