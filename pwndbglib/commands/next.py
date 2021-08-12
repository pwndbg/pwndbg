#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Stepping until an event occurs
"""

import argparse

import gdb

import pwndbglib.commands
import pwndbglib.next


@pwndbglib.commands.ArgparsedCommand("Breaks at the next jump instruction.", aliases=["nextjump"])
@pwndbglib.commands.OnlyWhenRunning
def nextjmp():
    """Breaks at the next jump instruction"""
    if pwndbglib.next.break_next_branch():
        pwndbglib.commands.context.context()


parser = argparse.ArgumentParser(description="""Breaks at the next call instruction""")
parser.add_argument("symbol_regex", type=str, default=None, nargs="?", help="A regex matching the name of next symbol to be broken on before calling.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def nextcall(symbol_regex=None):
    """Breaks at the next call instruction"""
    if pwndbglib.next.break_next_call(symbol_regex):
        pwndbglib.commands.context.context()


@pwndbglib.commands.ArgparsedCommand("""Breaks at next return-like instruction""")
@pwndbglib.commands.OnlyWhenRunning
def nextret():
    """Breaks at next return-like instruction"""
    if pwndbglib.next.break_next_ret():
        pwndbglib.commands.context.context()


@pwndbglib.commands.ArgparsedCommand("""Breaks at next return-like instruction by 'stepping' to it""")
@pwndbglib.commands.OnlyWhenRunning
def stepret():
    """Breaks at next return-like instruction by 'stepping' to it"""
    while pwndbglib.proc.alive and not pwndbglib.next.break_next_ret() and pwndbglib.next.break_next_branch():
        # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
        # We need to step so that we take this branch instead of ignoring it
        gdb.execute('si')
        continue

    if pwndbglib.proc.alive:
        pwndbglib.commands.context.context()


@pwndbglib.commands.ArgparsedCommand("""Breaks at the next instruction that belongs to the running program""")
@pwndbglib.commands.OnlyWhenRunning
def nextproginstr():
    """Breaks at the next instruction that belongs to the running program"""
    if pwndbglib.next.break_on_program_code():
        pwndbglib.commands.context.context()


parser = argparse.ArgumentParser(description="""Sets a breakpoint on the instruction after this one""")
parser.add_argument("addr", type=int, default=None, nargs="?", help="The address to break after.")
@pwndbglib.commands.ArgparsedCommand(parser, aliases=["so"])
@pwndbglib.commands.OnlyWhenRunning
def stepover(addr=None):
    """Sets a breakpoint on the instruction after this one"""
    pwndbglib.next.break_on_next(addr)


@pwndbglib.commands.ArgparsedCommand("Breaks at the next syscall not taking branches.", aliases=["nextsc"])
@pwndbglib.commands.OnlyWhenRunning
def nextsyscall():
    """
    Breaks at the next syscall not taking branches.
    """
    while pwndbglib.proc.alive and not pwndbglib.next.break_next_interrupt() and pwndbglib.next.break_next_branch():
        continue

    if pwndbglib.proc.alive:
        pwndbglib.commands.context.context()


@pwndbglib.commands.ArgparsedCommand("Breaks at the next syscall by taking branches.", aliases=["stepsc"])
@pwndbglib.commands.OnlyWhenRunning
def stepsyscall():
    """
    Breaks at the next syscall by taking branches.
    """
    while pwndbglib.proc.alive and not pwndbglib.next.break_next_interrupt() and pwndbglib.next.break_next_branch():
        # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
        # We need to step so that we take this branch instead of ignoring it
        gdb.execute('si')
        continue

    if pwndbglib.proc.alive:
        pwndbglib.commands.context.context()
