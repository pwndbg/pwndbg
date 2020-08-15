#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbg.arch
import pwndbg.commands
import pwndbg.regs
from pwndbg.color import context
from pwndbg.color import message


@pwndbg.commands.ArgparsedCommand('Print out ARM CPSR or xPSR register')
@pwndbg.commands.OnlyWhenRunning
def cpsr():
    arm_print_psr()

@pwndbg.commands.ArgparsedCommand('Print out ARM xPSR or CPSR register')
@pwndbg.commands.OnlyWhenRunning
def xpsr():
    arm_print_psr()

def arm_print_psr():
    if pwndbg.arch.current not in ('arm', 'armcm'):
        print(message.warn("This is only available on ARM"))
        return

    reg = 'cpsr' if pwndbg.arch.current == 'arm' else 'xpsr'
    print('%s %s' % (reg, context.format_flags(getattr(pwndbg.regs, reg), pwndbg.regs.flags[reg])))

