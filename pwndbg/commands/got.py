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
import pwndbg.wrappers
from pwndbg.color import red, green, light_yellow

parser = argparse.ArgumentParser(description='Show the state of the Global Offset Table')
parser.add_argument('name_filter', help='Filter results by passed name.',
                    type=str, nargs='?', default='')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def got(name_filter=''):
    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cs_out = pwndbg.wrappers.checksec("--file", local_path)

    file_out = pwndbg.wrappers.file(local_path)
    if "statically" in file_out:
        print(red("Binary is statically linked."))
        return

    readelf_out = pwndbg.wrappers.readelf("--relocs", local_path)

    jmpslots = '\n'.join(filter(lambda l: _extract_jumps(l),
                         readelf_out.splitlines()))

    if not len(jmpslots):
        print(red("NO JUMP_SLOT entries available in the GOT"))
        return

    if "PIE enabled" in cs_out:
        bin_text_base = pwndbg.memory.page_align(pwndbg.elf.entry())

    relro_status = "No RELRO"
    if "Full RELRO" in cs_out:
        relro_status = "Full RELRO"
    elif "Partial RELRO" in cs_out:
        relro_status = "Partial RELRO"

    print("\nGOT protection: %s | GOT functions: %d\n " % (green(relro_status), len(jmpslots.splitlines())))

    for line in jmpslots.splitlines():
        address, info, rtype, value, name = line.split()[:5]

        if name_filter not in name:
            continue

        address_val = int(address, 16)

        if "PIE enabled" in cs_out:  # if PIE, address is only the offset from the binary base address
            address_val = bin_text_base + address_val

        got_address = pwndbg.memory.pvoid(address_val)
        print("[%s] %s -> %s" % (address, light_yellow(name), pwndbg.chain.format(got_address)))


def _extract_jumps(l):
    try:
        if "JUMP" in l.split()[2]:
            return l
        else:
            return False
    except IndexError:
        return False
