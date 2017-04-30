#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import struct

import pwndbg.commands
import pwndbg.enhance
import pwndbg.chain
import pwndbg.which

from pwndbg.color import *


@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def got():
    '''
    Show the state of the Global Offset Table
    '''

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)

    for program in ['checksec', 'checksec.sh']:
        program = pwndbg.which.which(program)
        if program:
            argv = [program, "--file" , local_path]
            out = subprocess.check_output(argv).decode('utf-8')
            break
    else:
        print('Could not find checksec or checksec.sh in $PATH.')

    ispie = False
    bin_text_base = None
    if "PIE enabled" in out:
        ispie = True
        bin_text_base = pwndbg.memory.page_align(pwndbg.elf.entry())

    relro_status = "No RELRO"
    if "Full RELRO" in out:
        relro_status = "Full RELRO"
    if "Partial RELRO" in out:
        relro_status = "Partial RELRO"

    program = pwndbg.which.which("file")

    if program:
        argv = [program, local_path]
        out = subprocess.check_output(argv).decode('utf-8')

        if "statically" in out:
            print('File is statically linked.')
        else:
            program = pwndbg.which.which("readelf")
            if program:
                argv = [program, "-r", local_path]
                out = subprocess.check_output(argv).decode('utf-8')

                if "Error" in out:
                    print("Error during relocation info")
                else:
                    f_line = ""
                    for line in out.splitlines():
                        if "JUMP" not in line:
                            continue
                        else:
                            f_line = f_line + line + "\n"
                    if f_line == "":
                        print("NO JUMP_SLOT entries available in the GOT")
                    else:
                        f_line = [' '.join(x.split()).split(" ") for x in f_line.split("\n")][:-1]
                        print("\nGOT protection: %s | GOT functions: %d\n " %(green(relro_status), len(f_line)))

                        if pwndbg.arch.ptrsize == 4:
                            for (address, info, rtype, value, name) in f_line:
                                got_address = struct.unpack("<I", pwndbg.memory.read(int(address, 16), 4))[0]
                                print("[%s] %s -> %s" % (address, light_yellow(name), pwndbg.chain.format(got_address)))
                        else:
                            for (address, info, rtype, value, name, _ , _ ) in f_line:
                                if ispie:
                                    address = hex(bin_text_base + int(address, 16))
                                    got_address = struct.unpack("<Q",pwndbg.memory.read(int(address, 16), 8))[0]
                                    print("[%s] %s -> %s" % (address, light_yellow(name),pwndbg.chain.format(got_address)))
                                else:
                                    got_address = struct.unpack("<Q", pwndbg.memory.read(int(address, 16), 8))[0]
                                    print("[%s] %s -> %s" % (address,light_yellow(name),pwndbg.chain.format(got_address)))
            else:
                print('Could not find readelf in $PATH')
    else:
        print('Could not find file command in $PATH.')
