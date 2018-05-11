#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import binascii
import codecs
import os
import struct

import pwndbg.arch
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.config
import pwndbg.enhance
import pwndbg.search
import pwndbg.vmmap
from pwndbg.color import message

saved = set()


def print_search_hit(address):
    """Prints out a single search hit.

    Arguments:
        address(int): Address to print
    """
    if not address:
        return

    vmmap = pwndbg.vmmap.find(address)
    if vmmap:
        region = os.path.basename(vmmap.objfile)
    else:
        region = '[mapped]'

    region = region.ljust(15)

    region = M.get(address, region)
    addr = M.get(address)
    display = pwndbg.enhance.enhance(address)
    print(region, addr, display)

parser = argparse.ArgumentParser(description='Search memory for asm code')
parser.add_argument('asm-pattern', type=str, help='asm pattern to look for')
parser.add_argument('mapping', type=str, nargs='?', default=None,
                    help='Mapping to search [e.g. libc]')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def asmsearch(asm_pattern, mapping):

    if save is None:
        save = bool(pwndbg.config.auto_save_search)

    if hex:
        try:
            value = codecs.decode(value, 'hex')
        except binascii.Error as e:
            print('invalid input for type hex: {}'.format(e))
            return

    # Convert to an integer if needed, and pack to bytes
    if type not in ('string', 'bytes'):
        value = pwndbg.commands.fix_int(value)
        value &= pwndbg.arch.ptrmask
        fmt = {
            'little': '<',
            'big': '>'
        }[pwndbg.arch.endian] + {
            'byte': 'B',
            'short': 'H',
            'word': 'H',
            'dword': 'L',
            'qword': 'Q'
        }[type]

        # Work around Python 2.7.6 struct.pack / unicode incompatibility
        # See https://github.com/pwndbg/pwndbg/pull/336 for more information.
        fmt = str(fmt)

        try:
            value = struct.pack(fmt, value)
        except struct.error as e:
            print('invalid input for type {}: {}'.format(type, e))
            return

    # Null-terminate strings
    elif type == 'string':
        value = value.encode()
        value += b'\x00'

    # Find the mappings that we're looking for
    mappings = pwndbg.vmmap.get()

    if mapping_name:
        mappings = [m for m in mappings if mapping_name in m.objfile]

    if not mappings:
        print(message.error("Could not find mapping %r" % mapping_name))
        return

    # Prep the saved set if necessary
    global saved
    if save:
        saved = set()

    # Perform the search
    for address in pwndbg.search.search(value,
                                        mappings=mappings,
                                        executable=executable,
                                        writable=writable):

        if next and address not in saved:
            continue

        if save:
            saved.add(address)

        print_search_hit(address)
