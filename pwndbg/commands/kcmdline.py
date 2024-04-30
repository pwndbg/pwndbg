from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.gdblib.kernel
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Return the kernel commandline (/proc/cmdline).")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kcmdline() -> None:
    print(pwndbg.gdblib.kernel.kcmdline())
