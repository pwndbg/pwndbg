"""
Wrapper for shell commands.
"""

import os

import pwndbg.commands
import pwndbg.lib.which

pwncmd_names = ["asm", "constgrep", "disasm", "pwn", "unhex"]
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

pwncmds = list(filter(pwndbg.lib.which.which, pwncmd_names))
shellcmds = list(filter(pwndbg.lib.which.which, shellcmd_names))


def register_shell_function(cmd, deprecated=False):
    def handler(*a):
        if os.fork() == 0:
            os.execvp(cmd, (cmd,) + a)
        os.wait()
        print(
            "This command is deprecated in Pwndbg. Please use the GDB's built-in syntax for running shell commands instead: !%s <args>"
            % cmd
        )

    doc = "Invokes `{}` shell command".format(cmd)
    if deprecated:
        doc += " (deprecated)"

    handler.__name__ = str(cmd)
    handler.__doc__ = doc

    pwndbg.commands.Command(handler, shell=True)


for cmd in pwncmds:
    register_shell_function(cmd)

for cmd in shellcmds:
    register_shell_function(cmd, deprecated=True)
