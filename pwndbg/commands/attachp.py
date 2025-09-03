from __future__ import annotations

import argparse
import datetime
import os
import stat
import time
from typing import List
from typing import NamedTuple
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
    "how to determine the process to attach when multiple candidates exists",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=_OPTIONS,
)

parser = argparse.ArgumentParser(
    description="""Attaches to a given pid, process name, process found with partial argv match or to a device file.

This command wraps the original GDB `attach` command to add the ability
to debug a process with a given name or partial name match. In such cases,
the process identifier is fetched via the `pidof <name>` command first. If no
matches are found, then it uses the `ps -eo pid,args` command to search for
partial name matches.

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
parser.add_argument("--retry", action="store_true", help="retry until a target is found")
parser.add_argument("--user", type=str, default=None, help="username or uid to filter by")
parser.add_argument(
    "-e",
    "--exact",
    action="store_true",
    help="get the pid only for an exact command name match",
)
parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    help="get pids also for partial cmdline matches etc",
)
parser.add_argument(
    "target",
    nargs="?",
    default=None,
    type=str,
    help="pid, process name, part of cmdline to be matched or device file to attach to (uses current loaded file name if not provided)",
)


import psutil


def find_pids(target: str, user: str | None, exact: bool, all: bool) -> List[int]:
    # Note: we can't use `ps -C <target>` because this does not accept process names with spaces
    # so target='a b' would actually match process names 'a' and 'b' here
    # so instead, we will filter by process name or full cmdline later on
    # if provided, filter by effective username or uid; otherwise, select all processes

    current_pid = os.getpid()

    pids_exact_match_cmd = []
    pids_partial_match_cmd = []
    pids_partial_match_args = []

    iter_process = psutil.process_iter(["pid", "name", "cmdline", "username"])
    iter_process = filter(lambda p: p.pid != current_pid, iter_process)
    if user is not None:
        iter_process = filter(lambda p: proc.username() == user, iter_process)

    for proc in iter_process:
        try:
            cmdline = proc.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # The process no longer exists or we don't have permission
            continue
        else:
            if not cmdline:
                continue

            cmd = cmdline[0]
            args = " ".join(cmdline)

            if target == cmd:
                pids_exact_match_cmd.append(proc.pid)
            elif target in cmd:
                pids_partial_match_cmd.append(proc.pid)
            elif target in args:
                pids_partial_match_args.append(proc.pid)

    if exact and all:
        return pids_exact_match_cmd + pids_partial_match_cmd + pids_partial_match_args
    elif exact:
        return pids_exact_match_cmd
    elif all:
        return pids_exact_match_cmd + pids_partial_match_cmd + pids_partial_match_args
    else:
        return pids_exact_match_cmd or pids_partial_match_cmd or pids_partial_match_args


class ProcessInfo(NamedTuple):
    pid: int
    user: str
    elapsed: str
    command: str
    start_time: float


def resolve_target_process(
    pids: List[int],
    method: str,
    no_truncate: bool,
) -> int | None:
    proc_infos: List[ProcessInfo] = []

    for pid in pids:
        try:
            proc = psutil.Process(pid)
            start_time = proc.create_time()
            proc_infos.append(
                ProcessInfo(
                    proc.pid,
                    proc.username(),
                    str(datetime.timedelta(seconds=int(time.time() - start_time))),
                    " ".join(proc.cmdline()),
                    start_time,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            continue

    if not proc_infos:
        print(message.error("No accessible processes found."))
        return None

    # Sort by start time (oldest first)
    proc_infos.sort(key=lambda x: x.start_time)

    if method == _OLDEST:
        return proc_infos[0].pid
    elif method == _NEWEST:
        return proc_infos[-1].pid
    else:
        print(
            message.warn(
                f'Multiple processes found. Current resolution method is "{method}". '
                f"Run `config attachp-resolution-method` to see more information."
            )
        )

        headers = ["pid", "user", "elapsed", "command"]
        showindex: Union[bool, range] = False if method == _NONE else range(1, len(proc_infos) + 1)

        # Cast proc_infos for printing
        table_proc_infos = [
            [str(o.pid), str(o.user), str(o.elapsed), str(o.command)] for o in proc_infos
        ]

        # Calculate column width for truncation
        test_table = tabulate(table_proc_infos, headers=headers, showindex=showindex)
        table_width = len(test_table.splitlines()[1])
        max_command_width = max(len(row.command) for row in proc_infos)
        max_col_widths = max(max_command_width - (table_width - get_window_size()[1]), 10)

        # Truncate commands
        if not no_truncate:
            for row in table_proc_infos:
                row[3] = _truncate_string(row[3], max_col_widths)

        # Show the table
        msg = tabulate(
            table_proc_infos, headers=headers, showindex=showindex, maxcolwidths=max_col_widths
        )
        print(message.notice(msg))

        if method == _NONE:
            print(message.warn("Use `attach <pid>` to attach"))
            return None
        elif method == _ASK:
            while True:
                prompt = message.notice(f"Which process to attach to? (1-{len(proc_infos)}) ")
                try:
                    inp = input(prompt).strip()
                except EOFError:
                    return None
                try:
                    choice = int(inp)
                    if 1 <= choice <= len(proc_infos):
                        return proc_infos[choice - 1].pid
                except ValueError:
                    continue
        else:
            raise Exception("unreachable")


@pwndbg.commands.Command(parser, category=CommandCategory.START)
def attachp(
    target: str, no_truncate: bool, retry: bool, exact: bool, all: bool, user: str | None = None
) -> None:
    # As a default, the user may want to attach to a binary name taken from currently loaded file name
    if target is None:
        bin_path = pwndbg.aglib.proc.exe
        if bin_path is None:
            print(
                message.error(
                    "No target name/pid/cmdline provided and no binary loaded in the debugger"
                )
            )
            print(message.error("(could not find the process name to attach to)"))
            return

        target = os.path.basename(bin_path)
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
            pids = find_pids(target, user, exact, all)
            if not pids and retry:
                user_filter = "" if not user else f" and user={user}"
                print(
                    message.warn(
                        f"Looking for pids for target={target}{user_filter} in a loop. Hit CTRL+C to cancel"
                    )
                )
                while not pids:
                    pids = find_pids(target, user, exact, all)

            if not pids:
                print(message.error(f"Process {target} not found"))
                return

            if len(pids) > 1:
                method = pwndbg.config.attachp_resolution_method
                resolved_target = resolve_target_process(pids, method.value, no_truncate)
            else:
                resolved_target = pids[0]

    if resolved_target is None:
        return

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
