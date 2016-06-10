#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
        print(subprocess.check_output(['checksec', local_path]).decode(), end='')
    except:
        try:
            print(subprocess.check_output(['checksec.sh', '--file', local_path]).decode(), end='')
        except:
            try:
                print(subprocess.check_output(['checksec', '--file', local_path]).decode(), end='')
            except:
                print(pwndbg.color.red(
                    'An error occurred when calling checksec. ' \
                    'Make sure the checksec binary is in your PATH.'
                ))
