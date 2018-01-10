#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.commands
import pwndbg.memory
import pwndbg.symbol
import pwndbg.vmmap
from pwndbg.color import message


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
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
    addr = pwndbg.memory.u64(addr)
    free = []

    while addr and pwndbg.memory.peek(addr):
        free.append(addr)
        size   = pwndbg.memory.u64(addr)

        in_use = size & 1
        size   &= ~3

        linkedlist = (addr + 8 + size - 0x10) & pwndbg.arch.ptrmask

        try:
            bk = pwndbg.memory.u64(linkedlist)
        except:
            bk = None

        try:
            fd = pwndbg.memory.u64(linkedlist+8)
        except:
            fd = None

        print('    %#x %#x %s' % (addr, size, '*' if in_use else ''))
        addr = bk

    print()
    return free

def heap_allocations(addr, free):
    while addr and pwndbg.memory.peek(addr):
        size   = pwndbg.memory.u64(addr)
        in_use = size & 1
        flags  = size & 3
        done   = not (size & 2)
        size   &= ~3

        if size > 0x1000:
            print(message.error("FOUND CORRUPTION OR END OF DATA"))

        data = ''

        if not in_use or addr in free:
            print(message.hint("%#016x - usersize=%#x - [FREE %i]" % (addr, size, flags)))

            linkedlist = (addr + 8 + size - 0x10) & pwndbg.arch.ptrmask

            if not pwndbg.memory.peek(linkedlist):
                print('Corrupted? (%#x)' % linkedlist)

            bk = pwndbg.memory.u64(linkedlist)
            fd = pwndbg.memory.u64(linkedlist+8)

            print("  @ %#x" % linkedlist)
            print("    bk: %#x" % bk)
            print("    fd: %#x" % fd)
        else:
            print(message.notice("%#016x - usersize=%#x" % (addr, size)))
            pwndbg.commands.hexdump.hexdump(addr+8, size)

        addr += size + 8
        print()



@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ll(addr=0x637128):
    """
    .bss:0000000000637128 ; core_entry *core_list
    .bss:0000000000637128 core_list       dq ?                    ; DATA XREF: start_main_randomize+19Eo
    """
    fd = pwndbg.memory.u64(addr)
    print('%16s%#16s %#16s %#16s %#16s' % ('', 'o','v','bk','fd'))

    while fd:
        o = pwndbg.memory.u64(fd)
        v = pwndbg.memory.u64(o)

        v = pwndbg.symbol.get(v-0x10) or hex(v)

        at = fd
        bk = pwndbg.memory.u64(fd+8)
        fd  = pwndbg.memory.u64(fd+16)
        print('@ %#-15x%#16x %16s %#16x %#16x' % (at, o,v,bk,fd))
