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


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextjmp(*args):
    """Breaks at the next jump instruction"""
    if pwndbg.next.break_next_branch():
        pwndbg.commands.context.context()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextjump(*args):
    """Breaks at the next jump instruction"""
    nextjmp(*args)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextcall(*args):
    """Breaks at the next call instruction"""
    if pwndbg.next.break_next_call():
        pwndbg.commands.context.context()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def stepover(*args):
    """Sets a breakpoint on the instruction after this one"""
    pwndbg.next.break_on_next(*args)


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def so(*args):
    """Alias for stepover"""
    stepover(*args)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def next_syscall(*args):
    """
    Breaks at the next syscall.
    """
    while not pwndbg.next.break_next_interrupt() and pwndbg.next.break_next_branch():
        continue
    pwndbg.commands.context.context()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextsc(*args):
    """
    Breaks at the next syscall.
    """
    next_syscall(*args)
