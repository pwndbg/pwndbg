import functools
import subprocess
from subprocess import STDOUT

import pwndbg.commands
import pwndbg.lib.which


class OnlyWithCommand:
    def __init__(self, *commands):
        self.all_cmds = list(map(lambda cmd: cmd[0] if isinstance(cmd, list) else cmd, commands))
        for command in commands:
            self.cmd = command if isinstance(command, list) else [command]
            self.cmd_path = pwndbg.lib.which.which(self.cmd[0])
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
                raise OSError("Could not find command(s) %s in $PATH" % ", ".join(self.all_cmds))

        return _OnlyWithCommand


def call_cmd(cmd):
    return subprocess.check_output(cmd, stderr=STDOUT).decode("utf-8")
