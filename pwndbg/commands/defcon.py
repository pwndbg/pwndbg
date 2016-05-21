from __future__ import print_function
import gdb

import pwndbg.vmmap
import pwndbg.commands
import pwndbg.memory

from pwndbg.color import bold, blue, green, red

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def heap(addr=0x2aaaaaaaf000):
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



def heap_freebins(addr=0x060E360):
    print(bold('Linked List'))

    # addr = 0x0602558
    addr = 0x060E360
    print('    ' + hex(addr))
    addr = pwndbg.memory.u64(addr)
    free = []

    while True:
        if not pwndbg.memory.peek(addr):
            break

        free.append(addr)
        size   = pwndbg.memory.u64(addr)
        in_use = size & 1
        size   &= ~3

        linkedlist = addr + 8 + size - 0x10

        bk = pwndbg.memory.u64(linkedlist)
        fd = pwndbg.memory.u64(linkedlist+8)
        print('    %#x %#x %s' % (addr, size, '*' if in_use else ''))

        addr = bk
    
    print()
    return free

def heap_allocations(addr, free):
    while True:
        if not pwndbg.memory.peek(addr):
            break

        size   = pwndbg.memory.u64(addr)
        in_use = size & 1
        flags  = size & 3
        done   = not (size & 2)
        size   &= ~3

        if size > 0x1000:
            print(red(bold("FOUND CORRUPTION OR END OF DATA")))

        data = ''

        if not in_use or addr in free:
            print(blue(bold("%#016x - usersize=%#x - [FREE %i]" % (addr, size, flags))))

            linkedlist = addr + 8 + size - 0x10

            bk = pwndbg.memory.u64(linkedlist)
            fd = pwndbg.memory.u64(linkedlist+8)

            print("  @ %#x" % linkedlist)
            print("    bk: %#x" % bk)
            print("    fd: %#x" % fd)
        else:
            print(green(bold("%#016x - usersize=%#x" % (addr, size))))
            pwndbg.commands.hexdump.hexdump(addr+8, size)

        addr += size + 8
        print()

