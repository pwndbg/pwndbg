#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Stepping until an event occurs
"""

import argparse

import gdb

import pwndbg.commands
import pwndbg.next


@pwndbg.commands.ArgparsedCommand("Breaks at the next jump instruction.", aliases=["nextjump"])
@pwndbg.commands.OnlyWhenRunning
def nextjmp():
    """Breaks at the next jump instruction"""
    if pwndbg.next.break_next_branch():
        pwndbg.commands.context.context()


parser = argparse.ArgumentParser(description="""Breaks at the next call instruction""")
parser.add_argument("symbol_regex", type=str, default=None, nargs="?", help="A regex matching the name of next symbol to be broken on before calling.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def nextcall(symbol_regex=None):
    """Breaks at the next call instruction"""
    if pwndbg.next.break_next_call(symbol_regex):
        pwndbg.commands.context.context()


@pwndbg.commands.ArgparsedCommand("""Breaks at next return-like instruction""")
@pwndbg.commands.OnlyWhenRunning
def nextret():
    """Breaks at next return-like instruction"""
    if pwndbg.next.break_next_ret():
        pwndbg.commands.context.context()


@pwndbg.commands.ArgparsedCommand("""Breaks at next return-like instruction by 'stepping' to it""")
@pwndbg.commands.OnlyWhenRunning
def stepret():
    """Breaks at next return-like instruction by 'stepping' to it"""
    while pwndbg.proc.alive and not pwndbg.next.break_next_ret() and pwndbg.next.break_next_branch():
        # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
        # We need to step so that we take this branch instead of ignoring it
        gdb.execute('si')
        continue

    if pwndbg.proc.alive:
        pwndbg.commands.context.context()


@pwndbg.commands.ArgparsedCommand("""Breaks at the next instruction that belongs to the running program""")
@pwndbg.commands.OnlyWhenRunning
def nextproginstr():
    """Breaks at the next instruction that belongs to the running program"""
    if pwndbg.next.break_on_program_code():
        pwndbg.commands.context.context()


parser = argparse.ArgumentParser(description="""Sets a breakpoint on the instruction after this one""")
parser.add_argument("addr", type=int, default=None, nargs="?", help="The address to break after.")
@pwndbg.commands.ArgparsedCommand(parser, aliases=["so"])
@pwndbg.commands.OnlyWhenRunning
def stepover(addr=None):
    """Sets a breakpoint on the instruction after this one"""
    pwndbg.next.break_on_next(addr)


@pwndbg.commands.ArgparsedCommand("Breaks at the next syscall not taking branches.",aliases=["nextsc"])
@pwndbg.commands.OnlyWhenRunning
def nextsyscall():
    """
    Breaks at the next syscall not taking branches.
    """
    while pwndbg.proc.alive and not pwndbg.next.break_next_interrupt() and pwndbg.next.break_next_branch():
        continue

    if pwndbg.proc.alive:
        pwndbg.commands.context.context()


@pwndbg.commands.ArgparsedCommand("Breaks at the next syscall by taking branches.",aliases=["stepsc"])
@pwndbg.commands.OnlyWhenRunning
def stepsyscall():
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
