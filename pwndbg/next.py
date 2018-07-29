#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Commands for setting temporary breakpoints on the next
instruction of some type (call, branch, etc.)
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re

import capstone
import gdb

import pwndbg.disasm
import pwndbg.regs
from pwndbg.color import message

jumps = set((
    capstone.CS_GRP_CALL,
    capstone.CS_GRP_JUMP,
    capstone.CS_GRP_RET,
    capstone.CS_GRP_IRET
))

interrupts = set((capstone.CS_GRP_INT,))


def next_int(address=None):
    """
    If there is a syscall in the current basic black,
    return the instruction of the one closest to $PC.

    Otherwise, return None.
    """
    if address is None:
        ins = pwndbg.disasm.one(pwndbg.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.disasm.one(address)
    while ins:
        if set(ins.groups) & jumps:
            return None
        if set(ins.groups) & interrupts:
            return ins
        ins = pwndbg.disasm.one(ins.next)

    return None


def next_branch(address=None):
    if address is None:
        ins = pwndbg.disasm.one(pwndbg.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.disasm.one(address)
    while ins:
        if set(ins.groups) & jumps:
            return ins
        ins = pwndbg.disasm.one(ins.next)

    return None


def break_next_branch(address=None):
    ins = next_branch(address)

    if ins:
        gdb.Breakpoint("*%#x" % ins.address, internal=True, temporary=True)
        gdb.execute('continue', from_tty=False, to_string=True)
        return ins


def break_next_interrupt(address=None):
    ins = next_int(address)

    if ins:
        gdb.Breakpoint("*%#x" % ins.address, internal=True, temporary=True)
        gdb.execute('continue', from_tty=False, to_string=True)
        return ins


def break_next_call(symbol_regex=None):
    while pwndbg.proc.alive:
        ins = break_next_branch()

        if not ins:
            break

        # continue if not a call
        if capstone.CS_GRP_CALL not in ins.groups:
            continue

        # return call if we don't search for a symbol
        if not symbol_regex:
            return ins

        # return call if we match target address
        if ins.target_const and re.match('%s$' % symbol_regex, hex(ins.target)):
            return ins

        # return call if we match symbol name
        if ins.symbol and re.match('%s$' % symbol_regex, ins.symbol):
            return ins


def break_next_ret(address=None):
    while pwndbg.proc.alive:
        ins = break_next_branch(address)

        if not ins:
            break

        if capstone.CS_GRP_RET in ins.groups:
            return ins


def break_on_program_code():
    """
    Breaks on next instruction that belongs to process' objfile code.
    :return: True for success, False when process ended or when pc is at the code.
    """
    mp = pwndbg.proc.mem_page
    start = mp.start
    end = mp.end

    if start <= pwndbg.regs.pc < end:
        print(message.error('The pc is already at the binary objfile code. Not stepping.'))
        return False

    while pwndbg.proc.alive:
        gdb.execute('si', from_tty=False, to_string=False)

        addr = pwndbg.regs.pc
        if start <= addr < end:
            return True

    return False


def break_on_next(address=None):
    address = address or pwndbg.regs.pc
    ins = pwndbg.disasm.one(address)

    gdb.Breakpoint("*%#x" % (ins.address + ins.size), temporary=True)
    gdb.execute('continue', from_tty=False, to_string=True)
