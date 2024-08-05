from __future__ import annotations

import argparse
import os
import stat
from subprocess import CalledProcessError
from subprocess import check_output
from typing import Union

import gdb
from tabulate import tabulate

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.ui import get_window_size

_NONE = "none"
_OLDEST = "oldest"
_NEWEST = "newest"
_ASK = "ask"
_OPTIONS = [_NONE, _OLDEST, _NEWEST, _ASK]

pwndbg.config.add_param(
    "attachp-resolution-method",
    _ASK,
    f'how to determine the process to attach when multiple candidates exists ("{_OLDEST}", "{_NEWEST}", "{_NONE}" or "{_ASK}"(default))',
)

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

parser.add_argument("--no-truncate", action="store_true", help="dont truncate command args")
parser.add_argument("target", type=str, help="pid, process name or device file to attach to")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.START)
def attachp(no_truncate, target) -> None:
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
                try:
                    ps_output = check_output(["ps", "-eo", "pid,args"], universal_newlines=True)
                except FileNotFoundError:
                    print(message.error("Error: did not find `ps` command"))
                    return
                except CalledProcessError:
                    pids = []

                target_list = [part for part in target.split() if len(part) >= 2]
                for line in ps_output.strip().split("\n")[1:]:
                    process_info = line.split()
                    if len(process_info) <= 1:
                        continue
                    pid = process_info[0]
                    command = process_info[1]
                    if any(part in command for part in target_list):
                        pids.append(pid)

            if not pids:
                print(message.error(f"Process {target} not found"))
                return

            if len(pids) > 1:
                method = pwndbg.config.attachp_resolution_method

                if method not in _OPTIONS:
                    print(
                        message.warn(
                            f'Invalid value for `attachp-resolution-method` config. Fallback to default value("{_ASK}").'
                        )
                    )
                    method = _ASK

                try:
                    ps_output = check_output(
                        [
                            "ps",
                            "--no-headers",
                            "-ww",
                            "-p",
                            ",".join(pids),
                            "-o",
                            "pid,ruser,etime,args",
                            "--sort",
                            "+lstart",
                        ]
                    ).decode()
                except FileNotFoundError:
                    print(message.error("Error: did not find `ps` command"))
                    print(
                        message.warn(f"Use `attach <pid>` instead (found pids: {', '.join(pids)})")
                    )
                    return
                except CalledProcessError:
                    print(message.error("Error: failed to get process details"))
                    print(
                        message.warn(f"Use `attach <pid>` instead (found pids: {', '.join(pids)})")
                    )
                    return

                print(
                    message.warn(
                        f'Multiple processes found. Current resolution method is "{method}". Run the command `config attachp-resolution-method` to see more informations.'
                    )
                )

                # Here, we can safely use split to capture each field
                # since none of the columns except args can contain spaces
                proc_infos = [row.split(maxsplit=3) for row in ps_output.splitlines()]
                if method == _OLDEST:
                    resolved_target = int(proc_infos[0][0])
                elif method == _NEWEST:
                    resolved_target = int(proc_infos[-1][0])
                else:
                    headers = ["pid", "user", "elapsed", "command"]
                    showindex: Union[bool, range] = (
                        False if method == _NONE else range(1, len(proc_infos) + 1)
                    )

                    # calculate max_col_widths to fit window width
                    test_table = tabulate(proc_infos, headers=headers, showindex=showindex)
                    table_orig_width = len(test_table.splitlines()[1])
                    max_command_width = max(len(command) for _, _, _, command in proc_infos)
                    max_col_widths = max(
                        max_command_width - (table_orig_width - get_window_size()[1]), 10
                    )

                    # truncation
                    if not no_truncate:
                        for info in proc_infos:
                            info[-1] = _truncate_string(info[-1], max_col_widths)

                    msg = tabulate(
                        proc_infos,
                        headers=headers,
                        showindex=showindex,
                        maxcolwidths=max_col_widths,
                    )
                    print(message.notice(msg))

                    if method == _NONE:
                        print(message.warn("use `attach <pid>` to attach"))
                        return
                    elif method == _ASK:
                        while True:
                            msg = message.notice(f"which process to attach?(1-{len(proc_infos)}) ")
                            try:
                                inp = input(msg).strip()
                            except EOFError:
                                return
                            try:
                                choice = int(inp)
                                if not (1 <= choice <= len(proc_infos)):
                                    continue
                            except ValueError:
                                continue
                            break
                        resolved_target = int(proc_infos[choice - 1][0])
                    else:
                        raise Exception("unreachable")
            else:
                resolved_target = int(pids[0])

    print(message.on(f"Attaching to {resolved_target}"))
    try:
        gdb.execute(f"attach {resolved_target}")
    except gdb.error as e:
        print(message.error(f"Error: {e}"))
        return


def _is_device(path) -> bool:
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return False

    if stat.S_ISCHR(mode):
        return True

    return False


def _truncate_string(s: str, length: int):
    TRUNCATE_FILLER = " ... "
    if len(s) < length:
        return s
    truncate_point = (length - len(TRUNCATE_FILLER)) // 2
    result = s[:truncate_point]
    result += TRUNCATE_FILLER
    result += s[-(length - len(result)) :]
    return result
