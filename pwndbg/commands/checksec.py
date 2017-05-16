#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import subprocess

import pwndbg.commands
import pwndbg.which


parser = argparse.ArgumentParser()
parser.description = '''
    Prints out the binary security settings. Attempts to call binjitsu checksec falling back to checksec.sh.
'''

parser.add_argument('file', type=str, nargs='?', default=None, help='Local binary path')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def checksec(file=None):

    local_path = file or pwndbg.file.get_file(pwndbg.proc.exe)

    for program in ['checksec', 'checksec.sh']:
        program = pwndbg.which.which(program)

        if program:
            return subprocess.call([program, '--file', local_path])
    else:
        print('Could not find checksec or checksec.sh in $PATH.')
