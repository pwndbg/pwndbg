import argparse

import pwndbg.commands
import pwndbg.gdblib.kernel

parser = argparse.ArgumentParser(description="Outputs the kernel version (/proc/version)")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenQemuKernel
def kversion():
    print(pwndbg.gdblib.kernel.kversion())
