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
    if pwndbg.next.break_next_call(*args):
        pwndbg.commands.context.context()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextret(*args):
    """Breaks at next return-like instruction"""
    if pwndbg.next.break_next_ret():
        pwndbg.commands.context.context()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def stepret(*args):
    """Breaks at next return-like instruction by 'stepping' to it"""
    while pwndbg.proc.alive and not pwndbg.next.break_next_ret() and pwndbg.next.break_next_branch():
        # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
        # We need to step so that we take this branch instead of ignoring it
        gdb.execute('si')
        continue

    if pwndbg.proc.alive:
        pwndbg.commands.context.context()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextproginstr(*args):
    """Breaks at the next instruction that belongs to the running program"""
    if pwndbg.next.break_on_program_code():
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
def nextsyscall(*args):
    """
    Breaks at the next syscall not taking branches.
    """
    while pwndbg.proc.alive and not pwndbg.next.break_next_interrupt() and pwndbg.next.break_next_branch():
        continue

    if pwndbg.proc.alive:
        pwndbg.commands.context.context()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextsc(*args):
    """
    Breaks at the next syscall not taking branches.
    """
    nextsyscall(*args)


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def stepsyscall(*args):
    """
    Breaks at the next syscall by taking branches.
    """
    while pwndbg.proc.alive and not pwndbg.next.break_next_interrupt() and pwndbg.next.break_next_branch():
        # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
        # We need to step so that we take this branch instead of ignoring it
        gdb.execute('si')
        continue

    if pwndbg.proc.alive:
        pwndbg.commands.context.context()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def stepsc(*args):
    stepsyscall(*args)
