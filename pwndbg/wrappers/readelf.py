#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re

import pwndbg.wrappers

cmd_name = "readelf"

@pwndbg.wrappers.OnlyWithCommand(cmd_name)
def get_jmpslots():
    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [get_jmpslots.cmd_path, "--relocs", local_path]
    readelf_out = pwndbg.wrappers.call_cmd(cmd)

    return filter(_extract_jumps, readelf_out.splitlines())

def _extract_jumps(line):
    '''
     Checks for records in `readelf --relocs <binary>` which has type e.g. `R_X86_64_JUMP_SLO`
     NOTE: Because of that we DO NOT display entries that are not writeable (due to FULL RELRO)
     as they have `R_X86_64_GLOB_DAT` type.

    It might be good to display them seperately in the future.
    '''
    try:
        if "JUMP" in line.split()[2]:
            return line
        else:
            return False
    except IndexError:
        return False

@pwndbg.wrappers.OnlyWithCommand(cmd_name)
def get_load_segment_info():
    '''
    Looks for LOAD sections by parsing the output of `readelf --program-headers <binary>`
    '''
    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [get_jmpslots.cmd_path, "--program-headers", local_path]
    readelf_out = pwndbg.wrappers.call_cmd(cmd)

    segments = []
    load_found = False

    # Output from readelf is 
    # Type           Offset             VirtAddr           PhysAddr
    #                FileSiz            MemSiz             Flags  Align
    # LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
    #                0x0000000000000830 0x0000000000000830  R E    0x200000
    # Account for this using two regular expressions
    re_first = re.compile(r"\s+LOAD\s+(0x[0-9A-Fa-f]+) (0x[0-9A-Fa-f]+) (0x[0-9A-Fa-f]+)")
    re_secnd = re.compile(r"\s+(0x[0-9A-Fa-f]+) (0x[0-9A-Fa-f]+)  (.)(.)(.)\s+(0x[0-9A-Fa-f]+)")
    hex2int = lambda x: int(x, 16)

    for line in readelf_out.splitlines():
        if "LOAD" in line:
            load_found = True
            offset, vaddr, paddr = map(hex2int, re_first.match(line).groups())
        elif load_found:
            fsize, msize, read, write, execute, align = re_secnd.match(line).groups()
            fsize, msize, align = map(hex2int, (fsize, msize, align))
            read = read == "R"
            write = write == "W"
            execute = execute == "E"

            segments.append({"Offset":   offset,
                             "VirtAddr": vaddr,
                             "PhysAddr": paddr,
                             "FileSiz": fsize,
                             "MemSiz": msize,
                             "FlagsRead": read,
                             "FlagsWrite": write,
                             "FlagsExecute": execute})

            load_found = False

    return segments
