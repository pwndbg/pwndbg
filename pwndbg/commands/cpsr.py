#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.arch
import pwndbg.commands
import pwndbg.regs
from pwndbg.color import context
from pwndbg.color import message


@pwndbg.commands.ArgparsedCommand('Print out ARM CPSR register')
@pwndbg.commands.OnlyWhenRunning
def cpsr():
    if pwndbg.arch.current != 'arm':
        print(message.warn("This is only available on ARM"))
        return

    cpsr = pwndbg.regs.cpsr

    N = cpsr & (1 << 31)
    Z = cpsr & (1 << 30)
    C = cpsr & (1 << 29)
    V = cpsr & (1 << 28)
    T = cpsr & (1 << 5)

    result = [
        context.flag_set('N') if N else context.flag_unset('n'),
        context.flag_set('Z') if Z else context.flag_unset('z'),
        context.flag_set('C') if C else context.flag_unset('c'),
        context.flag_set('V') if V else context.flag_unset('v'),
        context.flag_set('T') if T else context.flag_unset('t')
    ]

    print('CPSR %s %s %s %s' % (context.flag_value('%#x' % cpsr),
          context.flag_bracket('['), ' '.join(result), context.flag_bracket(']')))
