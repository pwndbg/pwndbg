#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import pwndbg.wrappers


@pwndbg.wrappers.OnlyWithCommand
def get_jmpslots():

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [get_jmpslots.command_path, "-r", local_path]
    readelf_out = subprocess.check_output(cmd).decode('utf-8')

    return '\n'.join(filter(lambda line: _extract_jumps(line), readelf_out.splitlines()))


def _extract_jumps(line):
    try:
        if "JUMP" in line.split()[2]:
            return line
        else:
            return False
    except IndexError:
        return False
