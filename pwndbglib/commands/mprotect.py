#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import gdb

import pwndbglib.chain
import pwndbglib.commands
import pwndbglib.enhance
import pwndbglib.file
import pwndbglib.which
import pwndbglib.wrappers.checksec
import pwndbglib.wrappers.readelf
from pwndbglib.color import message

parser = argparse.ArgumentParser(description='Calls mprotect. x86_64 only.')
parser.add_argument('addr', help='Page-aligned address to all mprotect on.',
                    type=int)
parser.add_argument('length', help='Count of bytes to call mprotect on. Needs '
                    'to be multiple of page size.',
                    type=int)
parser.add_argument('prot', help='Prot string as in mprotect(2). Eg. '
                    '"PROT_READ|PROT_EXEC"', type=str)

SYS_MPROTECT = 0x7d

prot_dict = {
    'PROT_NONE': 0x0,
    'PROT_READ': 0x1,
    'PROT_WRITE': 0x2,
    'PROT_EXEC': 0x4,
}

def prot_str_to_val(protstr):
    '''Heuristic to convert PROT_EXEC|PROT_WRITE to integer value.'''
    prot_int = 0
    for k in prot_dict:
        if k in protstr:
            prot_int |= prot_dict[k]
    return prot_int


@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
@pwndbglib.commands.OnlyAmd64
def mprotect(addr, length, prot):
    '''Only x86_64.'''
    saved_rax = pwndbglib.regs.rax
    saved_rbx = pwndbglib.regs.rbx
    saved_rcx = pwndbglib.regs.rcx
    saved_rdx = pwndbglib.regs.rdx
    saved_rip = pwndbglib.regs.rip

    prot_int = prot_str_to_val(prot)
    gdb.execute('set $rax={}'.format(SYS_MPROTECT))
    gdb.execute('set $rbx={}'.format(addr))
    gdb.execute('set $rcx={}'.format(length))
    gdb.execute('set $rdx={}'.format(prot_int))

    saved_instruction_2bytes = pwndbglib.memory.read(pwndbglib.regs.rip, 2)

    # int 0x80
    pwndbglib.memory.write(pwndbglib.regs.rip, b'\xcd\x80')

    # execute syscall
    gdb.execute('stepi')

    print('mprotect returned {}'.format(pwndbglib.regs.rax))

    # restore registers and memory
    pwndbglib.memory.write(saved_rip, saved_instruction_2bytes)

    gdb.execute('set $rax={}'.format(saved_rax))
    gdb.execute('set $rbx={}'.format(saved_rbx))
    gdb.execute('set $rcx={}'.format(saved_rcx))
    gdb.execute('set $rdx={}'.format(saved_rdx))
    gdb.execute('set $rip={}'.format(saved_rip))

    pwndbglib.regs.rax = saved_rax
    pwndbglib.regs.rbx = saved_rbx
    pwndbglib.regs.rcx = saved_rcx
    pwndbglib.regs.rdx = saved_rdx
    pwndbglib.regs.rip = saved_rip

