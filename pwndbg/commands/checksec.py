#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess

import pwndbg.commands
import pwndbg.which
import pwndbg.wrappers

from pwndbg.color import red


@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def checksec(file=None):
    '''
    Prints out the binary security settings. Attempts to call the binjitsu
    checksec first, and then falls back to checksec.sh.
    '''
    local_path = file or pwndbg.file.get_file(pwndbg.proc.exe)
    checksec_out = pwndbg.wrappers.checksec(local_path)

    for x in checksec_out:
        print("%s %s %s" % (red(x),"—▸",checksec_out[x]))
