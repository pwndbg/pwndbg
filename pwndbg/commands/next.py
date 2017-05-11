#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Stepping until an event occurs
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.commands
import pwndbg.next


@pwndbg.commands.ArgparsedCommand('Breaks at the next jump instruction')
@pwndbg.commands.OnlyWhenRunning
def nextjmp():
    if pwndbg.next.break_next_branch():
        pwndbg.commands.context.context()


@pwndbg.commands.AliasCommand(nextjmp)
def nextjump():
    pass


@pwndbg.commands.ArgparsedCommand('Breaks at the next call instruction')
@pwndbg.commands.OnlyWhenRunning
def nextcall():
    if pwndbg.next.break_next_call():
        pwndbg.commands.context.context()


# TODO/FIXME ArgparsedCommand
@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def stepover(*args):
    """Sets a breakpoint on the instruction after this one"""
    pwndbg.next.break_on_next(*args)


# TODO/FIXME: AliasCommand
@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def so(*args):
    """Alias for stepover"""
    stepover(*args)


@pwndbg.commands.ArgparsedCommand('Breaks at the next syscall.')
@pwndbg.commands.OnlyWhenRunning
def next_syscall():
    while pwndbg.proc.alive and not pwndbg.next.break_next_interrupt() and pwndbg.next.break_next_branch():
        continue
    pwndbg.commands.context.context()


@pwndbg.commands.AliasCommand(next_syscall)
def nextsc():
    pass
