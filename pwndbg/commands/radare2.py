#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import subprocess

import pwndbg.commands

parser = argparse.ArgumentParser(description='Launches radare2',
                                 epilog="Example: r2 -- -S -AA")
parser.add_argument('--no-seek', action='store_true',
                    help='Do not seek to current pc')
parser.add_argument('arguments', nargs='*', type=str,
                    help='Arguments to pass to radare')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def r2(arguments, no_seek=False):
    filename = pwndbg.file.get_file(pwndbg.proc.exe)

    # Build up the command line to run
    cmd = ['radare2', filename]
    if not no_seek and pwndbg.proc.alive:
        cmd.extend(['-s', hex(pwndbg.regs.pc)])
    cmd += arguments

    try:
        subprocess.call(cmd)
    except Exception:
        print("Could not run radare2. Please ensure it's installed and in $PATH.")
