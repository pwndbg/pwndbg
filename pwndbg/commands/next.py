#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Stepping until an event occurs
"""
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
def nextj(*args):
    """Breaks at the next jump instruction"""
    nextjmp(*args)

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
def nextc(*args):
    """Breaks at the next call instruction"""
    nextcall(*args)


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def stepover(*args):
    """Sets a breakpoint on the instruction after this one"""
    pwndbg.next.break_on_next(*args)


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def so(*args):
    stepover(*args)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def next_syscall(*args):
    """
    Returns the address of the syscall inside the current basic block,
    or None.
    """
    if pwndbg.next.break_next_interrupt():
        pwndbg.commands.context.context()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nexti(*args):
    """
    Returns the address of the syscall inside the current basic block,
    or None.
    """
    next_syscall(*args)

