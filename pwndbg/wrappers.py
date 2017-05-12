#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Wrappers to external utilities.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess

import pwndbg.file

def checksec(path):
    '''
     Wrapper to checksec utility.
     Returns a dictionary for each protection supported containing the
     output of the utility.
    '''
    for program in ['checksec', 'checksec.sh']:
        program = pwndbg.which.which(program)
        if program:
            result = {}
            try:
                cs_out = subprocess.check_output([program, '--file', path]).decode('utf-8')
            except (OSError, subprocess.CalledProcessError):
                raise OSError("Error during execution of checksec command.\n",subprocess.CalledProcessError)

            if "Full RELRO" in cs_out:
                result['RELRO'] = "Full RELRO"
            if "Partial RELRO" in cs_out:
                result['RELRO'] = "Partial RELRO"
            if "No RELRO" in cs_out:
                result['RELRO'] = "No RELRO"

            if "Canary found" in cs_out:
                result['CANARY'] = "Canary found"
            else:
                result['CANARY'] = "Canary not found"

            if "NX enabled" in cs_out:
                result['NX'] = "NX enabled"
            else:
                result['NX'] = "NX not enabled"

            if "PIE enabled" in cs_out:
                result['PIE'] = "PIE enabled"
            else:
                result['PIE'] = "PIE not enabled"

            if "No RPATH" in cs_out:
                result['RPATH'] = "No RPATH"
            else:
                result['RPATH'] = "Yes RPATH"

            if "No RUNPATH" in cs_out:
                result['RUNPATH'] = "No RUNPATH"
            else:
                result['RUNPATH'] = "Yes RUNPATH"
            return result
    else:
        raise OSError("Could not find checksec or checksec.sh in $PATH.\n")


def file(path):
    """
     Utility: /usr/bin/file
    """
    program = pwndbg.which.which("file")
    argv = [program, path]
    if program:
        try:
            return subprocess.check_output(argv).decode('utf-8')
        except:
            raise OSError("Error during execution of file command", subprocess.CalledProcessError)
    else:
        raise OSError("Could not find file command in $PATH.")

def readelf(path,argv):
    """
     Utility: /usr/bin/readelf
    """
    program = pwndbg.which.which("readelf")
    if program:
        argv = [program, argv, path]
        try:
            readelf_out = subprocess.check_output(argv).decode('utf-8')
        except:
            raise OSError("Error during execution of readelf command.")
        return readelf_out

    else:
        raise OSError("Could not find readelf command in $PATH.")
