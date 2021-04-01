#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Wrapper for shell commands.
"""

import os

import gdb

import pwndbg.commands
import pwndbg.which

shellcmds = [
    "asm", # pwntools
    "awk",
    "bash",
    "cat",
    "chattr",
    "chmod",
    "chown",
    # "clear",
    "constgrep", # pwntools
    "cp",
    "cyclic", # pwntools
    "date",
    "diff",
    "disasm", # pwntools
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
    "pwn", # pwntools
    "rm",
    "sed",
    "sh",
    "sort",
    "ssh",
    "sudo",
    "tail",
    "top",
    "touch",
    "unhex", # pwntools
    "uniq",
    "vi",
    "vim",
    "w",
    "wget",
    "who",
    "whoami",
    "zsh",
]

shellcmds = filter(pwndbg.which.which, shellcmds)

def register_shell_function(cmd):
    def handler(*a):
        if os.fork() == 0:
            os.execvp(cmd, (cmd,) + a)
        os.wait()

    handler.__name__ = str(cmd)
    handler.__doc__ = 'Invokes {}'.format(cmd)

    pwndbg.commands.Command(handler, False)

for cmd in shellcmds:
    register_shell_function(cmd)
