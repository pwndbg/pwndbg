from __future__ import annotations

import functools
import subprocess
from subprocess import STDOUT
from typing import Callable
from typing import List
from typing import TypeVar

from pwnlib.util.misc import which
from typing_extensions import ParamSpec

import pwndbg.commands

P = ParamSpec("P")
T = TypeVar("T")


class OnlyWithCommand:
    def __init__(self, *commands: str | List[str]) -> None:
        self.all_cmds: List[str] = [cmd[0] if isinstance(cmd, list) else cmd for cmd in commands]
        for command in commands:
            self.cmd: List[str] = command if isinstance(command, list) else [command]
            self.cmd_path: str | None = which(self.cmd[0])
            if self.cmd_path:
                break

    def __call__(self, function: Callable[P, T]) -> Callable[P, T | None]:
        function.cmd = self.cmd

        @pwndbg.commands.OnlyWithFile
        @functools.wraps(function)
        def _OnlyWithCommand(*a: P.args, **kw: P.kwargs) -> T | None:
            if self.cmd_path:
                return function(*a, **kw)
            else:
                raise OSError(f"Could not find command(s) {', '.join(self.all_cmds)} in $PATH")

        return _OnlyWithCommand


def call_cmd(cmd: str | List[str]) -> str:
    return subprocess.check_output(cmd, stderr=STDOUT).decode("utf-8")
