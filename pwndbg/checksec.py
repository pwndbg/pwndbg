#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Wrapper to checksec utility.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess

import pwndbg.file

def checksec(path):
    for program in ['checksec', 'checksec.sh']:
        program = pwndbg.which.which(program)
        if program:
            result = {}
            try:
                cs_out = subprocess.check_output([program, '--file', path]).decode('utf-8')
            except:
                raise OSError("Error during execution of checksec command.\n")

            if "Full RELRO" in cs_out:
                result['RELRO'] = 2
            if "Partial RELRO" in cs_out:
                result['RELRO'] = 1
            if "No RELRO" in cs_out:
                result['RELRO'] = 0

            if "Canary found" in cs_out:
                result['CANARY'] = True
            else:
                result['CANARY'] = False

            if "NX enabled" in cs_out:
                result['NX'] = True
            else:
                result['NX'] = False

            if "PIE enabled" in cs_out:
                result['PIE'] = True
            else:
                result['PIE'] = False

            if "No RPATH" in cs_out:
                result['RPATH'] = False
            else:
                result['RPATH'] = True

            if "No RUNPATH" in cs_out:
                result['RUNPATH'] = False
            else:
                result['RUNPATH'] = True
            return result
    else:
        raise OSError("Could not find checksec or checksec.sh in $PATH.\n")

