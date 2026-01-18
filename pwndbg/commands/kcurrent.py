from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
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
_KCURRENT = None


def get_kcurrent() -> pwndbg.commands.ktask.Kthread | None:
    global _KCURRENT
    if _KCURRENT is None:
        return None
    for task in pwndbg.commands.ktask.get_ktasks():
        for _kthread in task.threads:
            if int(_kthread.thread) == int(_KCURRENT.thread):
                return _KCURRENT
    _KCURRENT = None  # the previously set KCURRENT doesn't exist anymore
    return None


def select_kthread_from_pid(
    pid: int | None, verbose: bool = True
) -> pwndbg.commands.ktask.Kthread | None:
    if not pwndbg.aglib.kernel.ktask.load_ktask_typeinfo():
        return None
    kthread = None
    if pid is None:
        if (kthread := get_kcurrent()) is not None:
            return kthread
        t = pwndbg.aglib.kernel.current_task()
        kthread = pwndbg.commands.ktask.Kthread(t)
        if not kthread:
            print(message.warn("current task not found"))
    else:
        for task in pwndbg.commands.ktask.get_ktasks():
            for _kthread in task.threads:
                if _kthread.pid == pid:
                    kthread = _kthread
                    break
            if kthread:
                break
        if not kthread:
            print(message.warn(f"ktask with pid {pid} not found"))
    return kthread


parser = argparse.ArgumentParser(
    description="Displays information about the stack of a kernel task."
)
parser.add_argument("pid", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.WarnOnKernelConfigRandstruct
def kstack(pid: int = None) -> None:
    task = select_kthread_from_pid(pid)
    if not task:
        return
    indent.print(task)
    if not task.stack:
        indent.print(message.warn("task has no stack"))
    with indent:
        indent.print(color.yellow("stack") + " @ " + pwndbg.chain.format(task.stack))
        canary = task.canary
        if canary:
            indent.print(color.red("canary") + f" = {canary:#x}")
        regs = task.pt_regs()
        if regs:
            namelen = max(len(reg) for reg, _ in regs)
            for reg, val in regs:
                reg = f"{reg:<{namelen}}"
                indent.print(color.red(reg) + " = " + pwndbg.chain.format(val))


parser = argparse.ArgumentParser(
    description="Displays information about fds accessible by a kernel task."
)
parser.add_argument("pid", nargs="?", type=int, help="")
parser.add_argument("--fd", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.WarnOnKernelConfigRandstruct
def kfile(pid: int = None, fd: int = None) -> None:
    thread = select_kthread_from_pid(pid)
    if not thread:
        return
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
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.WarnOnKernelConfigRandstruct
def kcurrent(pid: int = None, set_pid: bool = False, verbose: bool = True) -> None:
    kthread = get_kcurrent()
    if pid or not kthread:
        kthread = select_kthread_from_pid(pid, verbose)
    if verbose and kthread:
        indent.print(kthread)
    if set_pid and kthread:
        global _KCURRENT
        _KCURRENT = kthread
