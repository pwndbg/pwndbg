from __future__ import annotations

import argparse

import pwndbg.color as C
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.lib
from pwndbg.lib.exception import IndentContextManager
from pwndbg.lib.regs import BitFlags

indent = IndentContextManager()

fmode_flags = BitFlags([("R", 0), ("W", 1), ("X", 5)])

parser = argparse.ArgumentParser(
    description="Displays information about fds accessible by a process."
)
parser.add_argument("pid", nargs="?", type=int, help="")
parser.add_argument("--fd", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugSymbols
def kfile(pid=None, fd=None):
    if pid is None:
        print(M.warn("no pid specified"))
        return
    indent = IndentContextManager()
    threads = []
    for task in pwndbg.commands.ktask.get_ktasks():
        threads += task.threads
    for thread in threads:
        if thread.pid != pid:
            continue
        indent.print(thread)
        with indent:
            for i, file in thread.files():
                if fd is not None and i != fd:
                    continue
                addr = int(file)
                ops = int(file["f_op"])
                prefix = indent.prefix(f"[0x{i:02x}]")
                flags = C.context.format_flags(int(file["f_mode"]), fmode_flags)
                desc = f"ops @ {C.red(pwndbg.chain.format(ops, limit=0))}"
                indent.print(f"- {prefix} file @ {indent.addr_hex(addr)}: {desc}")
                private_data = int(file["private_data"])
                with indent:
                    indent.print(f"private: {indent.addr_hex(private_data)}, fmode: {flags}")
