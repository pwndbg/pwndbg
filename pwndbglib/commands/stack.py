
import gdb

import pwndbglib.arch
import pwndbglib.chain
import pwndbglib.commands
import pwndbglib.regs
import pwndbglib.vmmap


@pwndbglib.commands.ArgparsedCommand('Print out the stack addresses that contain return addresses.')
@pwndbglib.commands.OnlyWhenRunning
def retaddr():
    sp = pwndbglib.regs.sp
    stack = pwndbglib.vmmap.find(sp)

    # Enumerate all return addresses
    frame = gdb.newest_frame()
    addresses = []
    while frame:
        addresses.append(frame.pc())
        frame = frame.older()

    # Find all of them on the stack
    start = stack.vaddr
    stop = start + stack.memsz
    while addresses and start < sp < stop:
        value = pwndbglib.memory.u(sp)

        if value in addresses:
            index = addresses.index(value)
            del addresses[:index]
            print(pwndbglib.chain.format(sp))

        sp += pwndbglib.arch.ptrsize
