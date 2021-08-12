#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import gdb

import pwndbglib.commands
import pwndbglib.memory
import pwndbglib.symbol
import pwndbglib.vmmap
from pwndbglib.color import message

parser = argparse.ArgumentParser()
parser.description = "Print out the heap (defcon edition)."
parser.add_argument("addr", nargs="?", type=int, default=0x2aaaaaad5000, help="The address of the heap.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def defcon_heap(addr=0x2aaaaaad5000):
# def heap(addr=0x2aaaaaaaf000):
    free = []

    try:
        free = heap_freebins()
    except Exception as e:
        print(e)
        pass

    try:
        heap_allocations(addr, free)
    except Exception as e:
        print(e)
        pass



def heap_freebins(addr=0x0602558):
    print(message.notice('Linked List'))

    # addr = 0x0602558
    # addr = 0x060E360

    print('    ' + hex(addr))
    addr = pwndbglib.memory.u64(addr)
    free = []

    while addr and pwndbglib.memory.peek(addr):
        free.append(addr)
        size   = pwndbglib.memory.u64(addr)

        in_use = size & 1
        size   &= ~3

        linkedlist = (addr + 8 + size - 0x10) & pwndbglib.arch.ptrmask

        try:
            bk = pwndbglib.memory.u64(linkedlist)
        except:
            bk = None

        try:
            fd = pwndbglib.memory.u64(linkedlist + 8)
        except:
            fd = None

        print('    %#x %#x %s' % (addr, size, '*' if in_use else ''))
        addr = bk

    print()
    return free

def heap_allocations(addr, free):
    while addr and pwndbglib.memory.peek(addr):
        size   = pwndbglib.memory.u64(addr)
        in_use = size & 1
        flags  = size & 3
        done   = not (size & 2)
        size   &= ~3

        if size > 0x1000:
            print(message.error("FOUND CORRUPTION OR END OF DATA"))

        data = ''

        if not in_use or addr in free:
            print(message.hint("%#016x - usersize=%#x - [FREE %i]" % (addr, size, flags)))

            linkedlist = (addr + 8 + size - 0x10) & pwndbglib.arch.ptrmask

            if not pwndbglib.memory.peek(linkedlist):
                print('Corrupted? (%#x)' % linkedlist)

            bk = pwndbglib.memory.u64(linkedlist)
            fd = pwndbglib.memory.u64(linkedlist + 8)

            print("  @ %#x" % linkedlist)
            print("    bk: %#x" % bk)
            print("    fd: %#x" % fd)
        else:
            print(message.notice("%#016x - usersize=%#x" % (addr, size)))
            pwndbglib.commands.hexdump.hexdump(addr + 8, size)

        addr += size + 8
        print()



@pwndbglib.commands.Command
@pwndbglib.commands.OnlyWhenRunning
def ll(addr=0x637128):
    """
    .bss:0000000000637128 ; core_entry *core_list
    .bss:0000000000637128 core_list       dq ?                    ; DATA XREF: start_main_randomize+19Eo
    """
    fd = pwndbglib.memory.u64(addr)
    print('%16s%#16s %#16s %#16s %#16s' % ('', 'o','v','bk','fd'))

    while fd:
        o = pwndbglib.memory.u64(fd)
        v = pwndbglib.memory.u64(o)

        v = pwndbglib.symbol.get(v - 0x10) or hex(v)

        at = fd
        bk = pwndbglib.memory.u64(fd + 8)
        fd  = pwndbglib.memory.u64(fd + 16)
        print('@ %#-15x%#16x %16s %#16x %#16x' % (at, o,v,bk,fd))
