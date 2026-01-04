from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.chain
import pwndbg.color as color
import pwndbg.color.context as ctx_color
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.commands.ktask
from pwndbg.lib.exception import IndentContextManager
from pwndbg.lib.regs import BitFlags

indent = IndentContextManager()

fmode_flags = BitFlags([("R", 0), ("W", 1), ("X", 5)])
KCURRENT_PID = None
KCURRENT_PGD = None

parser = argparse.ArgumentParser(
    description="Displays information about fds accessible by a kernel task."
)
parser.add_argument("pid", nargs="?", type=int, help="")
parser.add_argument("--fd", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugInfo
def kfile(pid=None, fd=None):
    if pid is None:
        if KCURRENT_PID is None:
            kcurrent(None, set_pid=True, verbose=False)
        pid = KCURRENT_PID
    if pid is None:
        print(message.warn("no pid specified (either specify pid or set with kcurrent)"))
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
                prefix = indent.prefix(f"[fileno {i:03}]")
                flags = ctx_color.format_flags(int(file["f_mode"]), fmode_flags)
                desc = f"ops @ {color.red(pwndbg.chain.format(ops, limit=0))}"
                indent.print(f"- {prefix} file @ {indent.addr_hex(addr)}: {desc}")
                private_data = int(file["private_data"])
                with indent:
                    indent.print(f"private: {indent.addr_hex(private_data)}, fmode: {flags}")


parser = argparse.ArgumentParser(
    description="""
    Displays the current kernel task debugged by the debugger (gdb/lldb) if pid == None
    Displays the task with pid if pid != None.
    """
)
parser.add_argument("pid", nargs="?", type=int, help="")
parser.add_argument(
    "--set",
    dest="set_pid",
    action="store_true",
    help="sets the kernel task used for supported pwndbg commands (kfile, pagewalk, vmmap), this option does not change internal mem (purely effects how certain commands behaves)",
)


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugInfo
def kcurrent(pid=None, set_pid=False, verbose=True):
    global KCURRENT_PID, KCURRENT_PGD
    kthread = None
    if pid is None:
        kcurrent = pwndbg.aglib.kernel.current_task()
        kcurrent = pwndbg.aglib.memory.get_typed_pointer("struct task_struct", kcurrent)
        if kcurrent and pwndbg.aglib.memory.is_kernel(int(kcurrent)):
            pid = int(kcurrent["pid"])
    if pid is not None:
        for task in pwndbg.commands.ktask.get_ktasks():
            for _kthread in task.threads:
                if _kthread.pid == pid:
                    kthread = _kthread
    if kthread is None:
        print(message.warn("cannot find kernel task"))
        return
    if verbose:
        indent.print(kthread)
    if set_pid:
        mm = kthread.mm
        if not mm:
            print(message.warn("mm not found, current kernel task not set."))
            return
        KCURRENT_PID = pid
        KCURRENT_PGD = int(mm["pgd"])
