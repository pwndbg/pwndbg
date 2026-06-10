from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
import pwndbg.aglib.memory
import pwndbg.aglib.signal
import pwndbg.chain
import pwndbg.color.context as ctx_color
import pwndbg.commands
import pwndbg.commands.kbpf
import pwndbg.commands.ktask
import pwndbg.commands.parse_seccomp
from pwndbg import color
from pwndbg.color import message
from pwndbg.commands.ktask import Kthread
from pwndbg.lib.exception import IndentContextManager
from pwndbg.lib.regs import BitFlags
from pwndbg.lib.syscall import syscall_number_to_name

indent = IndentContextManager()

fmode_flags = BitFlags([("R", 0), ("W", 1), ("X", 5)])
_KCURRENT = None


def get_kcurrent() -> Kthread | None:
    global _KCURRENT
    if _KCURRENT is None:
        return None
    for task in pwndbg.commands.ktask.get_ktasks():
        for _kthread in task.threads:
            if int(_kthread.thread) == int(_KCURRENT.thread):
                return _KCURRENT
    _KCURRENT = None  # the previously set KCURRENT doesn't exist anymore
    return None


def select_kthread_from_pid(pid: int | None) -> Kthread | None:
    pwndbg.aglib.kernel.ktask.recover_ktask_typeinfo()
    kthread = None
    if pid is None:
        if (kthread := get_kcurrent()) is not None:
            return kthread
        t = pwndbg.aglib.kernel.current_task()
        if pwndbg.aglib.memory.is_kernel(t):
            kthread = Kthread(t)
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
        else:
            print(message.warn(f"ktask with pid {pid} not found"))
    return kthread


parser = argparse.ArgumentParser(description="Displays information about the stack of a task.")
parser.add_argument("pid", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.WarnOnKernelConfigRandstruct
def kstack(pid: int | None = None) -> None:
    task = select_kthread_from_pid(pid)
    if not task:
        return
    indent.print(task)
    if not task.stack:
        indent.print(message.warn("task has no stack"))
        return
    with indent:
        indent.print(color.yellow("stack") + " @ " + pwndbg.chain.format(task.stack))
        canary = task.canary
        if canary:
            indent.print(color.red("canary") + f" = {canary:#x}")
        regs, syscall_reg = task.pt_regs()
        if regs:
            # so that it doesn't warn on user addresses
            old_val = pwndbg.config.auto_explore_pages.value
            pwndbg.config.auto_explore_pages.value = "no"
            try:
                namelen = max(len(reg) for reg, _ in regs)
                for reg, val in regs:
                    _val = pwndbg.chain.format(val)
                    desc = syscall_number_to_name(val, pwndbg.aglib.arch.name)
                    if reg == syscall_reg and desc:
                        _val += f" ({color.red(desc)})"
                    reg = f"{reg:<{namelen}}"
                    indent.print(color.red(reg) + " = " + _val)
            finally:
                pwndbg.config.auto_explore_pages.value = old_val


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
def kfile(pid: int | None = None, fd: int | None = None) -> None:
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
            path = color.yellow(pwndbg.aglib.kernel.ktask.get_filepath(file))
            with indent:
                indent.print(
                    f"private: {indent.addr_hex(private_data)}, flags: {flags}, path: {path}"
                )


parser = argparse.ArgumentParser(description="Displays information about the namespcae of a task.")
parser.add_argument("pid", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
def knamespace(pid: int) -> None:
    thread = select_kthread_from_pid(pid)
    if not thread:
        return
    indent.print(thread)
    with indent:
        for name, val in thread.nsproxy:
            indent.print(color.yellow(name) + " @ " + pwndbg.chain.format(val))


parser = argparse.ArgumentParser(
    description="Displays information about the signal handlers of a user task."
)
parser.add_argument("pid", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
def ksighand(pid: int) -> None:
    thread = select_kthread_from_pid(pid)
    if not thread:
        return
    indent.print(thread)
    with indent:
        if not thread.user_task:
            indent.print(message.warn("not user task"))
            return
        for i, (handler, flags) in enumerate(thread.sighand):
            m = pwndbg.aglib.signal.PER_ARCH_SIGNAL_MAPPINGS[pwndbg.aglib.arch.name]
            if i not in m:
                continue
            name = color.blue(f"{m[i]:<10}")
            match handler:
                case 0:
                    handler = color.red("SIG_DFL")
                case 1:
                    handler = color.red("SIG_IGN")
                case _:
                    handler = pwndbg.chain.format(handler)
            flags = color.yellow(f"0x{flags:016x}")
            indent.print(name, flags, handler)


parser = argparse.ArgumentParser(
    description="Displays information about the seccomp of a user task."
)
parser.add_argument("pid", nargs="?", type=int, help="")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
def kseccomp(pid: int) -> None:
    thread = select_kthread_from_pid(pid)
    if not thread:
        return
    indent.print(thread)
    with indent:
        if not thread.user_task:
            indent.print(message.warn("not user task"))
            return
        progs = thread.seccomp()
        if progs is None:
            indent.print(message.warn("task not seccomp'd"))
            return
        for i, prog in enumerate(progs):
            pwndbg.commands.kbpf.print_bpf_prog_metadata(i, int(prog), prog, indent)
            result = pwndbg.commands.parse_seccomp._parse_seccomp(
                int(prog["orig_prog"]["filter"]), int(prog["orig_prog"]["len"])
            )
            for line in result.splitlines():
                indent.print(line)


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
    help="sets the kernel task used for supported pwndbg commands (kfile, kstack, knamespace, ksighand, kseccomp, pagewalk, vmmap), this option does not change internal memory (only effects how certain commands behaves)",
)


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.WarnOnKernelConfigRandstruct
def kcurrent(pid: int | None = None, set_pid: bool = False) -> None:
    kthread = select_kthread_from_pid(pid)
    if kthread is None:
        return
    indent.print(kthread)
    if set_pid:
        global _KCURRENT
        _KCURRENT = kthread
