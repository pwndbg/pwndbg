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

    cs_out = pwndbg.checksec.checksec()
    if not cs_out:
        return 'Could not find checksec or checksec.sh in $PATH.'

    file_out = pwndbg.file.file(local_path)
    if not file_out:
        return 'Could not find file command in $PATH.'
    if 'statically' in file_out:
        return 'Binary is statically linked.'

    jmpslots = pwndbg.elf.getjmpslots(local_path)
    if not jmpslots:
        return 'Could not find readelf command in $PATH.'
    if 'Error' in jmpslots:
        return 'Error during retrieving of relocation info.'
    if not len(jmpslots):
        return 'NO JUMP_SLOT entries available in the GOT'

    ispie = False
    bin_text_base = None
    if cs_out['PIE']:
        ispie = True
        bin_text_base = pwndbg.memory.page_align(pwndbg.elf.entry())

    relro_status = "No RELRO"
    if cs_out['RELRO'] == 2:
        relro_status = "Full RELRO"
    if cs_out['RELRO'] == 1:
        relro_status = "Partial RELRO"

    f_line = [' '.join(x.split()).split(" ") for x in jmpslots.split("\n")][:-1]
    print("\nGOT protection: %s | GOT functions: %d\n " %(green(relro_status), len(f_line)))

    if pwndbg.arch.ptrsize == 4:
        for (address, info, rtype, value, name) in f_line:
            addressval = int(address, 16)
            got_address = pwndbg.memory.pvoid(addressval)
            print("[%s] %s -> %s" % (address, light_yellow(name), pwndbg.chain.format(got_address)))
    else:
        for (address, info, rtype, value, name, _, _) in f_line:
            addressval = int(address,16)

            if ispie: # if PIE, address is only the offset from the binary base address
                addressval = bin_text_base + addressval

            got_address = pwndbg.memory.pvoid(addressval)
            print("[%s] %s -> %s" % (hex(addressval), light_yellow(name),pwndbg.chain.format(got_address)))

