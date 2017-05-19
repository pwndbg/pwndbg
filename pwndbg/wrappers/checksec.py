#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import pwndbg.wrappers

from pwndbg.wrappers import checksec_path

cmd_opt = {
           "file":"--file"
          }

@pwndbg.wrappers.OnlyWithFile(checksec_path)
def get_raw_out():
    return subprocess.check_output([checksec_path,cmd_opt["file"],pwndbg.file.get_file(pwndbg.proc.exe)]).decode('utf-8')


@pwndbg.wrappers.OnlyWithFile(checksec_path)
def relro_status():
    relro = "No RELRO"
    out = subprocess.check_output([checksec_path,cmd_opt["file"],pwndbg.file.get_file(pwndbg.proc.exe)]).decode('utf-8')
    if "Full RELRO" in out:
        relro = "Full RELRO"
    elif "Partial RELRO" in out:
        relro = "Partial RELRO"
    return relro

@pwndbg.wrappers.OnlyWithFile(checksec_path)
def pie_status():
    pie = "No PIE"
    out = subprocess.check_output([checksec_path,cmd_opt["file"],pwndbg.file.get_file(pwndbg.proc.exe)]).decode('utf-8')
    if "PIE enabled" in out:
        pie = "PIE enabled"
    return pie