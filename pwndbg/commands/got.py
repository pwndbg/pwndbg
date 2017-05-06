#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.commands
import pwndbg.checksec
import pwndbg.file
import pwndbg.enhance
import pwndbg.chain
import pwndbg.which

from pwndbg.color import green
from pwndbg.color import light_yellow


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithFile
def got():
    '''
    Show the state of the Global Offset Table
    '''

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cs_out = pwndbg.checksec.checksec(local_path)

    file_out = pwndbg.file.file(local_path)
    if "statically" in file_out:
        return "Binary is statically linked."

    jmpslots = pwndbg.elf.getjmpslots(local_path)
    if not len(jmpslots):
        return "NO JUMP_SLOT entries available in the GOT"

    if cs_out['PIE']:
        bin_text_base = pwndbg.memory.page_align(pwndbg.elf.entry())

    relro_status = "No RELRO"
    if cs_out['RELRO'] == 2:
        relro_status = "Full RELRO"
    if cs_out['RELRO'] == 1:
        relro_status = "Partial RELRO"

    print("\nGOT protection: %s | GOT functions: %d\n " % (green(relro_status), len(jmpslots.splitlines())))

    if pwndbg.arch.ptrsize == 4:
        for line in jmpslots.splitlines():
            address, info, rtype, value, name = line.split()
            got_address = pwndbg.memory.pvoid(int(address, 16))
            print("[%s] %s -> %s" % (address, light_yellow(name), pwndbg.chain.format(got_address)))
    else:
        for line in jmpslots.splitlines():
            address, info, rtype, value, name, _, _ = line.split()
            address_val = int(address,16)

            if cs_out['PIE']: # if PIE, address is only the offset from the binary base address
                address_val = bin_text_base + address_val

            got_address = pwndbg.memory.pvoid(address_val)
            print("[%s] %s -> %s" % (hex(address_val), light_yellow(name), pwndbg.chain.format(got_address)))

