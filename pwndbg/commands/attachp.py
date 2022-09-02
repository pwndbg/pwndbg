import argparse
import os
import stat
from subprocess import CalledProcessError
from subprocess import check_output

import gdb

import pwndbg.color.message as message
import pwndbg.commands

parser = argparse.ArgumentParser(
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
    to specify the program, and to load its symbol table."""
)

parser.add_argument("target", type=str, help="pid, process name or device file to attach to")


@pwndbg.commands.ArgparsedCommand(parser)
def attachp(target):
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
            except FileNotFoundError:
                print(message.error("Error: did not find `pidof` command"))
                return
            except CalledProcessError:
                pids = []

            if not pids:
                print(message.error("Process %s not found" % target))
                return

            if len(pids) > 1:
                print(message.warn("Found pids: %s (use `attach <pid>`)" % ", ".join(pids)))
                return

            resolved_target = int(pids[0])

    print(message.on("Attaching to %s" % resolved_target))
    try:
        gdb.execute("attach %s" % resolved_target)
    except gdb.error as e:
        print(message.error("Error: %s" % e))


def _is_device(path):
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return False

    if stat.S_ISCHR(mode):
        return True

    return False
