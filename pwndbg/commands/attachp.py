from __future__ import annotations

import argparse
import os
import stat
from subprocess import CalledProcessError
from subprocess import check_output

import gdb
import psutil
from tabulate import tabulate

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Attaches to a given pid, process name or device file.

This command wraps the original GDB `attach` command to add the ability
to debug a process with given name. In such case the process identifier is
fetched via the `pidof <name>` command.

Original GDB attach command help:
    Attach to a process or file outside of GDB.
    This command attaches to another target, of the same type as your last
    "target" command ("info files" will show your target stack).
    The command may take as argument a process id or a device file.
    For a process id, you must have permission to send the process a signal,
    and it must have the same effective uid as the debugger.
    When using "attach" with a process id, the debugger finds the
    program running in the process, looking first in the current working
    directory, or (if not found there) using the source file search path
    (see the "directory" command).  You can also use the "file" command
    to specify the program, and to load its symbol table.""",
)

parser.add_argument("target", type=str, help="pid, process name or device file to attach to")
parser.add_argument("--show_all", action="store_true", help="showing all output process tree and command")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.START)
def attachp(target, show_all=False) -> None:
    try:
        resolved_target = int(target)
    except ValueError:
        # GDB supposedly supports device files, so let's try it here...:
        #    <disconnect3d> hey, does anyone know what does `attach <device-file>` do?
        #    <disconnect3d> is this an alias for `target extended /dev/ttyACM0` or similar?
        #    <disconnect3d> I mean, `help attach` suggests that the `attach` command supports a device file target...
        #    <simark> I had no idea
        #    <simark> what you pass to attach is passed directly to target_ops::attach
        #    <simark> so it must be very target-specific
        #    <disconnect3d> how can it be target specific if it should  attach you to a target?
        #    <disconnect3d> or do you mean osabi/arch etc?
        #    <simark> in "attach foo", foo is interpreted by the target you are connected to
        #    <simark> But all targets I can find interpret foo as a PID
        #    <simark> So it might be that old targets had some other working mode
        if _is_device(target):
            resolved_target = target

        else:
            try:
                pids = check_output(["pidof", target]).decode().rstrip("\n").split(" ")
                pidsData = []
            except FileNotFoundError:
                print(message.error("Error: did not find `pidof` command"))
                return
            except CalledProcessError:
                pids = []

            if not pids:
                print(message.error(f"Process {target} not found"))
                return

            if len(pids) > 1:
                pidsData.append(["PID", "USER", "COMMAND", "PROCESS TREE"])
                for pid in pids:
                    pid = int(pid)

                    user = check_output(["ps", "-o", "user=", "-p", str(pid)]).decode().strip()
                    command = (
                        check_output(["ps", "-o", "cmd=", "-p", str(pid)]).decode()
                    )
                    process_tree = get_process_tree(pid, max_depth=2, full=show_all)

                    if len(command) >= 40 and not show_all:
                        command = command[:38] + "--(truncated)"

                    pidsData.append([pid, user, command, process_tree])

                # Format the final output message
                print(tabulate(pidsData, headers="firstrow", tablefmt="grid"))
                print(message.warn(f"\n Found pids: {', '.join(pids)} (use `attach <pid>`)"))
                return

            resolved_target = int(pids[0])

    print(message.on(f"Attaching to {resolved_target}"))
    try:
        gdb.execute(f"attach {resolved_target}")
    except gdb.error as e:
        print(message.error(f"Error: {e}"))


def get_process_tree(pid, max_depth=2, indent=0, full=False):
    def build_tree(process, depth):
        if depth > max_depth and not full:
            return

        process_info = process.as_dict(attrs=['pid', 'name'])
        process_str = " " * indent + f"{process_info['name']}({process_info['pid']}) \n"

        if depth < max_depth:
            for child in process.children():
                child_str = build_tree(child, depth + 1)
                if child_str:
                    process_str += child_str

        return process_str

    try:
        root_process = psutil.Process(pid)
        return build_tree(root_process, 0)
    except psutil.NoSuchProcess:
        return ""


def _is_device(path) -> bool:
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return False

    if stat.S_ISCHR(mode):
        return True

    return False
