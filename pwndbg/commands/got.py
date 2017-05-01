#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import struct

import pwndbg.commands
import pwndbg.commands.checksec
import pwndbg.enhance
import pwndbg.chain
import pwndbg.which

from pwndbg.color import *


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithFile
def got():
    '''
    Show the state of the Global Offset Table
    '''

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cs_out = pwndbg.commands.checksec._checksec()

    if not cs_out:
        print("Could not find checksec or checksec.sh in $PATH.")
        return

    program = pwndbg.which.which("file")
    if program:
        argv = [program, local_path]
        file_out = subprocess.check_output(argv).decode('utf-8')
        if "statically" in file_out:
            print('File is statically linked.')
            return
    else:
        print('Could not find file command in $PATH.')
        return

    program = pwndbg.which.which("readelf")
    if program:
        argv = [program, "-r", local_path]
        readelf_out = subprocess.check_output(argv).decode('utf-8')

        if "Error" in readelf_out:
            print("Error during retrieve of relocations info")
            return
    else:
        print('Could not find readelf in $PATH')
        return

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

    f_line = ""
    for line in readelf_out.splitlines():
        if "JUMP" not in line:
            continue
        else:
            f_line = f_line + line + "\n"
    if not f_line:
        print("NO JUMP_SLOT entries available in the GOT")
        return
    else:
        f_line = [' '.join(x.split()).split(" ") for x in f_line.split("\n")][:-1]
        print("\nGOT protection: %s | GOT functions: %d\n " %(green(relro_status), len(f_line)))

        if pwndbg.arch.ptrsize == 4:
            for (address, info, rtype, value, name) in f_line:
                got_address = struct.unpack("<I", pwndbg.memory.read(int(address, 16), 4))[0]
                print("[%s] %s -> %s" % (address, light_yellow(name), pwndbg.chain.format(got_address)))
        else:
            for (address, info, rtype, value, name, _, _) in f_line:
                addressval = int(address,16)

                if ispie: # if PIE, address is only the offset from the binary base address
                    addressval = bin_text_base + addressval

                got_address = struct.unpack("<Q",pwndbg.memory.read(addressval, 8))[0]
                print("[%s] %s -> %s" % (hex(addressval), light_yellow(name),pwndbg.chain.format(got_address)))

