from __future__ import annotations

import functools
import subprocess
from subprocess import STDOUT

from pwnlib.util.misc import which

import pwndbg.commands


class OnlyWithCommand:
    def __init__(self, *commands) -> None:
        self.all_cmds = list(map(lambda cmd: cmd[0] if isinstance(cmd, list) else cmd, commands))
        for command in commands:
            self.cmd = command if isinstance(command, list) else [command]
            self.cmd_path = which(self.cmd[0])
            if self.cmd_path:
                break

    def __call__(self, function):
        function.cmd = self.cmd

        @pwndbg.commands.OnlyWithFile
        @functools.wraps(function)
        def _OnlyWithCommand(*a, **kw):
            if self.cmd_path:
                return function(*a, **kw)
            else:
                raise OSError(f"Could not find command(s) {', '.join(self.all_cmds)} in $PATH")

        return _OnlyWithCommand


def call_cmd(cmd):
    return subprocess.check_output(cmd, stderr=STDOUT).decode("utf-8")
