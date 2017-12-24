#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.arch
import pwndbg.color
import pwndbg.commands
import pwndbg.regs


@pwndbg.commands.ArgparsedCommand('Print out ARM CPSR register')
@pwndbg.commands.OnlyWhenRunning
def cpsr():
    if pwndbg.arch.current != 'arm':
        print("This is only available on ARM")
        return

    cpsr = pwndbg.regs.cpsr

    N = cpsr & (1 << 31)
    Z = cpsr & (1 << 30)
    C = cpsr & (1 << 29)
    V = cpsr & (1 << 28)
    T = cpsr & (1 << 5)

    bold = pwndbg.color.bold

    result = [
        bold('N') if N else 'n',
        bold('Z') if Z else 'z',
        bold('C') if C else 'c',
        bold('V') if V else 'v',
        bold('T') if T else 't'
    ]

    print('cpsr %#x [ %s ]' % (cpsr, ' '.join(result)))
