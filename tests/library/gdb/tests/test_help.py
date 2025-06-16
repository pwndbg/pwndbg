from __future__ import annotations

import gdb

from pwndbg import commands


def test_command_help_strings(start_binary):
    """
    Tests whether the `help` command works for Pwndbg commands. We go through
    every command and check whether the value of `help <command>` matches the
    help string we pass to the Debugger-agnostic API when it's being registered.
    """

    for command in commands.commands:
        help_str = gdb.execute(f"help {command.command_name}", from_tty=False, to_string=True)
        if command.help_str is None:
            assert help_str.strip() == "This command is not documented."
        else:
            truth = [
                line.strip() for line in command.help_str.splitlines() if len(line.strip()) > 0
            ]
            gdb_out = [line.strip() for line in help_str.splitlines() if len(line.strip()) > 0]

            # We check both of these cases since for some commands GDB will
            # output the list of aliases as the first line.
            assert truth == gdb_out or truth == gdb_out[1:]
