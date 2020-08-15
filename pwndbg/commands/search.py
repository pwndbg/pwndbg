#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

auto_save = pwndbg.config.Parameter('auto-save-search', False,
                        'automatically pass --save to "search" command')

parser = argparse.ArgumentParser(description='''
Search memory for byte sequences, strings, pointers, and integer values
''')
parser.add_argument('-t', '--type', choices=['byte','short','word','dword','qword','pointer','string','bytes'],
                    help='Size of search target', default='bytes', type=str)
parser.add_argument('-1', '--byte', dest='type', action='store_const', const='byte',
                    help='Search for a 1-byte integer')
parser.add_argument('-2', '--word', '--short', dest='type', action='store_const', const='word',
                    help='Search for a 2-byte integer')
parser.add_argument('-4', '--dword', dest='type', action='store_const', const='dword',
                    help='Search for a 4-byte integer')
parser.add_argument('-8', '--qword', dest='type', action='store_const', const='qword',
                    help='Search for an 8-byte integer')
parser.add_argument('-p', '--pointer', dest='type', action='store_const', const='pointer',
                    help='Search for a pointer-width integer')
parser.add_argument('-x', '--hex', action='store_true',
                    help='Target is a hex-encoded (for bytes/strings)')
parser.add_argument('-s', '--string', action='store_true',
                    help='Target is a raw string')
parser.add_argument('-e', '--executable', action='store_true',
                    help='Search executable segments only')
parser.add_argument('-w', '--writable', action='store_true',
                    help='Search writable segments only')
parser.add_argument('value', type=str,
                    help='Value to search for')
parser.add_argument('mapping_name', type=str, nargs='?', default=None,
                    help='Mapping to search [e.g. libc]')
parser.add_argument('--save', action='store_true', default=None,
                    help='Save results for --resume.  Default comes from config %r' % auto_save.name)
parser.add_argument('--no-save', action='store_false', default=None, dest='save',
                    help='Invert --save')
parser.add_argument('-n', '--next', action='store_true',
                    help='Search only locations returned by previous search with --save')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def search(type, hex, string, executable, writable, value, mapping_name, save, next):
    # Adjust pointer sizes to the local architecture
    if type == 'pointer':
        type = {
            4: 'dword',
            8: 'qword'
        }[pwndbg.arch.ptrsize]

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
