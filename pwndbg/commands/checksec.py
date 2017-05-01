#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess

import pwndbg.commands
import pwndbg.which


@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def checksec(file=None):
    '''
    Prints out the binary security settings. Attempts to call the binjitsu
    checksec first, and then falls back to checksec.sh.
    '''
    local_path = file or pwndbg.file.get_file(pwndbg.proc.exe)

    for program in ['checksec', 'checksec.sh']:
        program = pwndbg.which.which(program)

        if program:
            return subprocess.call([program, '--file', local_path])
    else:
        print('Could not find checksec or checksec.sh in $PATH.')

@pwndbg.commands.OnlyWithFile
def _checksec():
    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    result = {}

    for program in ['checksec', 'checksec.sh']:
        program = pwndbg.which.which(program)
        if program:
            cs_out = subprocess.check_output([program, '--file', local_path]).decode('utf-8')

            if "Full RELRO" in cs_out:
                result['RELRO'] = 2
            if "Partial RELRO" in cs_out:
                result['RELRO'] = 1
            if "No RELRO" in cs_out:
                result['RELRO'] = 0

            if "Canary found" in cs_out:
                result['CANARY'] = 1
            else:
                result['CANARY'] = 0

            if "NX enabled" in cs_out:
                result['NX'] = 1
            else:
                result['NX'] = 0

            if "PIE enabled" in cs_out:
                result['PIE'] = 1
            else:
                result['PIE'] = 0

            if "No RPATH" in cs_out:
                result['RPATH'] = 0
            else:
                result['RPATH'] = 1

            if "No RUNPATH" in cs_out:
                result['RUNPATH'] = 0
            else:
                result['RUNPATH'] = 1

            return result
    else:
        return None