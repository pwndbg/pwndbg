#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Heap commands.
"""
from __future__ import print_function
import argparse
import gdb
import pwndbg.commands

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def brk(n=0):
    '''Get the address of brk(n=0)'''
    gdb.execute('call brk(%i)' % n)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def sbrk(n=0):
    '''Get the address of sbrk(n=0)'''
    gdb.execute('call sbrk(%i)' % n)




p = argparse.ArgumentParser(prog='hheap')

p.add_argument('--size',
               help='Heap size.  May be expressed as an integer or range (e.g. 32-64).')
p.add_argument('--verbose', action='store_true',
               help='Print more information')
p.add_argument('--free', action='store_true',
               help='Only show free slots')
p.add_argument('address', type=int, default=0,
               help='Heap allocation to display')

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def hheap(*a):
    """Prints out heap information.
    """ + p.format_help()
    try:
        args = p.parse_args(a)
    except SystemExit:
        return

