#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Wrapper for shell commands.
"""
from __future__ import print_function
import os

import gdb
import pwndbg.commands

shellcmds = [
    "awk",
    "bash",
    "cat",
    "chattr",
    "chmod",
    "chown",
    "clear",
    "cp",
    "date",
    "diff",
    "egrep",
    "find",
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

def register_shell_function(cmd):
    def handler(*a):
        """Invokes %s""" % cmd
        if os.fork() == 0:
            os.execvp(cmd, (cmd,) + a)
        os.wait()
    handler.__name__ = cmd
    pwndbg.commands.Command(handler, False)

for cmd in shellcmds:
    register_shell_function(cmd)
