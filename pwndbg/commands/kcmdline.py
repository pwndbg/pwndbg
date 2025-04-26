from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Return the kernel commandline (/proc/cmdline).")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def kcmdline() -> None:
    print(pwndbg.aglib.kernel.kcmdline())
