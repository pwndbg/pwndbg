#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb

import pwndbg.commands
from pwndbg.color import message

parser = argparse.ArgumentParser(description='''
Set all passed registers to the same value
Examples:
    setregs rax,rbx,rcx 0x1337
    setregs r8,r9,r10,r11,r12,r13 $rsp+8
''')
parser.add_argument('regs', type=str, help='Registers to be changed, comma delimited (without space)')
parser.add_argument('value', type=pwndbg.commands.sloppy_gdb_parse, help='Value to set registers to')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def setregs(regs, value):
    regs = [r.strip() for r in regs.split(',')]
    
    target_reg_names = set(pwndbg.regs.current)

    missing = [r for r in regs if r not in target_reg_names]
    if missing:
        miss_str = ','.join(missing)
        curr_str = ','.join(target_reg_names)
        print(message.error('Could not find registers: {}.\nKnown regs: {}'.format(miss_str, curr_str)))
        return

    for reg in regs:
        gdb.execute('set ${} = ({})'.format(reg, value))
