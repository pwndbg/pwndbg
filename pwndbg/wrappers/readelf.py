#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import pwndbg.wrappers

from pwndbg.wrappers import readelf_path

cmd_opt = {
           "relocs":"-r",
           "header":"-h"
          }

@pwndbg.wrappers.OnlyWithFile(readelf_path)
def get_jmpslots():
    readelf_out = subprocess.check_output([readelf_path,cmd_opt["relocs"],pwndbg.file.get_file(pwndbg.proc.exe)]).decode('utf-8')
    return '\n'.join(filter(lambda l: _extract_jumps(l),readelf_out.splitlines()))


def _extract_jumps(l):
    try:
        if "JUMP" in l.split()[2]:
            return l
        else:
            return False
    except IndexError:
        return False