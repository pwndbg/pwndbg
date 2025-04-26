from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Outputs the kernel version (/proc/version).")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kversion() -> None:
    print(pwndbg.aglib.kernel.kversion())
