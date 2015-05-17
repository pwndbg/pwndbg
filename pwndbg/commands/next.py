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
    pwndbg.next.break_next_branch()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextj(*args):
    nextjmp(*args)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextjump(*args):
    nextjmp(*args)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextcall(*args):
    pwndbg.next.break_next_call()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextc(*args):
    nextcall(*args)

