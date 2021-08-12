#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbglib.arch
import pwndbglib.commands
import pwndbglib.regs
from pwndbglib.color import context
from pwndbglib.color import message


@pwndbglib.commands.ArgparsedCommand('Print out ARM CPSR or xPSR register')
@pwndbglib.commands.OnlyWhenRunning
def cpsr():
    arm_print_psr()

@pwndbglib.commands.ArgparsedCommand('Print out ARM xPSR or CPSR register')
@pwndbglib.commands.OnlyWhenRunning
def xpsr():
    arm_print_psr()

def arm_print_psr():
    if pwndbglib.arch.current not in ('arm', 'armcm'):
        print(message.warn("This is only available on ARM"))
        return

    reg = 'cpsr' if pwndbglib.arch.current == 'arm' else 'xpsr'
    print('%s %s' % (reg, context.format_flags(getattr(pwndbglib.regs, reg), pwndbglib.regs.flags[reg])))

