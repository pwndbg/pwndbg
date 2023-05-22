import argparse

import pwndbg
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.kernel import log

parser = argparse.ArgumentParser(description="Outputs the kernel log buffer")


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["dmesg", "klog"], category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
def kdmesg() -> None:
    # TODO/FIXME: add filtering capabilities (e.g. by text/device/subsystem/log level/?)
    kernel_log = log.KernelLog()
    for log_entry in kernel_log.get_logs():
        ts = float(log_entry["timestamp"]) / 1e9
        text = log_entry["text"]
        print(f"[{ts:12.6f}] {text}")
