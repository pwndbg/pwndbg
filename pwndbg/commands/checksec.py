#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb
import pwndbg.commands

import subprocess

@pwndbg.commands.Command
def checksec():
    '''
    Prints out the binary security settings. Attempts to call the binjitsu
    checksec first, and then falls back to checksec.sh.
    '''
    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    try:
        subprocess.call(['checksec', local_path])
    except:
        try:
            subprocess.call(['checksec.sh', '--file', local_path])
        except:
            print(pwndbg.color.red(
                'An error occurred when calling checksec. ' \
                'Make sure the checksec binary is in your PATH.'
            ))
