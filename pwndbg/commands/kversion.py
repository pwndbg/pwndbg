import argparse

import pwndbg.commands
import pwndbg.gdblib.kernel

parser = argparse.ArgumentParser(description="Outputs the kernel version (/proc/version).")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def kversion() -> None:
    print(pwndbg.gdblib.kernel.kversion())
