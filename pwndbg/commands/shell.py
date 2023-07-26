"""
Wrapper for shell commands.
"""

from __future__ import annotations

import os

from pwnlib.util.misc import which

import pwndbg.commands
from pwndbg.commands import CommandCategory

pwncmd_names = ["constgrep", "disasm", "pwn", "unhex"]
shellcmd_names = [
    "awk",
    "bash",
    "cat",
    "chattr",
    "chmod",
    "chown",
    # "clear",
    "cp",
    "date",
    "diff",
    "egrep",
    # "find", don't expose find as its an internal gdb command
    "grep",
    "htop",
    "id",
    # "kill",
    # "killall",
    "less",
    # "ln",
    "ls",
    "man",
    "mkdir",
    "mktemp",
    "more",
    "mv",
    "nano",
    "nc",
    "ping",
    "pkill",
    "ps",
    "pstree",
    "pwd",
    "rm",
    "sed",
    "sh",
    "sort",
    "ssh",
    "sudo",
    "tail",
    "top",
    "touch",
    "uniq",
    "vi",
    "vim",
    "w",
    "wget",
    "who",
    "whoami",
    "zsh",
]

pwncmds = list(filter(which, pwncmd_names))
shellcmds = list(filter(which, shellcmd_names))


def register_shell_function(cmd, deprecated=False) -> None:
    def handler(*a) -> None:
        if os.fork() == 0:
            os.execvp(cmd, (cmd,) + a)
        os.wait()
        print(
            f"This command is deprecated in Pwndbg. Please use the GDB's built-in syntax for running shell commands instead: !{cmd} <args>"
        )

    doc = f"Invokes `{cmd}` shell command"
    if deprecated:
        doc += " (deprecated)"

    handler.__name__ = str(cmd)
    handler.__doc__ = doc

    pwndbg.commands.Command(handler, shell=True, category=CommandCategory.SHELL)


for cmd in pwncmds:
    register_shell_function(cmd)

for cmd in shellcmds:
    register_shell_function(cmd, deprecated=True)
