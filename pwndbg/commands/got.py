#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.file
import pwndbg.which
import pwndbg.wrappers.readelf
import pwndbg.wrappers.checksec

from pwndbg.color import green
from pwndbg.color import light_yellow


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithFile
def got():
    '''
    Show the state of the Global Offset Table
    '''

    relro_status = pwndbg.wrappers.checksec.relro_status()
    pie_status = pwndbg.wrappers.checksec.pie_status()
    jmpslots = pwndbg.wrappers.readelf.get_jmpslots()

    if pwndbg.wrappers.file.is_statically_linked():
        return "Binary is statically linked"
    if not len(jmpslots):
        return "NO JUMP_SLOT entries available in the GOT"
    if "PIE enabled" in pie_status:
        bin_text_base = pwndbg.memory.page_align(pwndbg.elf.entry())

    print("\nGOT protection: %s | GOT functions: %d\n " % (green(relro_status), len(jmpslots.splitlines())))

    for line in jmpslots.splitlines():
        address, info, rtype, value, name = line.split()[:5]
        address_val = int(address, 16)

        if "PIE enabled" in pie_status: # if PIE, address is only the offset from the binary base address
            address_val = bin_text_base + address_val

        got_address = pwndbg.memory.pvoid(address_val)
        print("[%s] %s -> %s" % (hex(address_val), light_yellow(name), pwndbg.chain.format(got_address)))

