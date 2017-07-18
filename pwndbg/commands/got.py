#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.file
import pwndbg.which
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf

from pwndbg.color import green
from pwndbg.color import light_yellow
from pwndbg.color import red

parser = argparse.ArgumentParser(description='Show the state of the Global Offset Table')
parser.add_argument('name_filter', help='Filter results by passed name.',
                    type=str, nargs='?', default='')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def got(name_filter=''):

    relro_status = pwndbg.wrappers.checksec.relro_status()
    pie_status = pwndbg.wrappers.checksec.pie_status()
    jmpslots = list(pwndbg.wrappers.readelf.get_jmpslots())

    if not len(jmpslots):
        print(red("NO JUMP_SLOT entries available in the GOT"))
        return
    if "PIE enabled" in pie_status:
        bin_text_base = pwndbg.memory.page_align(pwndbg.elf.entry())

    print("\nGOT protection: %s | GOT functions: %d\n " % (green(relro_status), len(jmpslots)))

    for line in jmpslots:
        address, info, rtype, value, name = line.split()[:5]

        if name_filter not in name:
            continue

        address_val = int(address, 16)

        if "PIE enabled" in pie_status: # if PIE, address is only the offset from the binary base address
            address_val = bin_text_base + address_val

        got_address = pwndbg.memory.pvoid(address_val)
        print("[0x%x] %s -> %s" % (address_val, light_yellow(name), pwndbg.chain.format(got_address)))