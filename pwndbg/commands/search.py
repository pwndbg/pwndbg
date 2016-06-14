from __future__ import print_function
from __future__ import unicode_literals

import argparse
import codecs
import os
import struct

import gdb
import pwndbg.color
import pwndbg.commands
import pwndbg.enhance
import pwndbg.search
import pwndbg.vmmap


def print_search(value, *a, **kw):
    hits = set()

    for address in pwndbg.search.search(value, *a, **kw):
        if not address:
            continue

        if address in hits:
            continue

        hits.add(address)

        vmmap = pwndbg.vmmap.find(address)
        if vmmap:
            region = os.path.basename(vmmap.objfile)
        else:
            region = '[mapped]'

        region = region.ljust(15)

        region = pwndbg.color.get(address, region)
        addr = pwndbg.color.get(address)
        display = pwndbg.enhance.enhance(address)
        print(region,addr,display)

parser = argparse.ArgumentParser(description='''
Search memory for byte sequences, strings, pointers, and integer values
''')
parser.add_argument('-t', '--type', choices=['byte','short','dword','qword','pointer','string','bytes'],
                    help='Size of search target', default='bytes', type=str)
parser.add_argument('-1', '--byte', dest='type', action='store_const', const='byte',
                    help='Search for a 1-byte integer')
parser.add_argument('-2', '--word', dest='type', action='store_const', const='word',
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
parser.add_argument('mapping', type=str, nargs='?', default=None,
                    help='Mapping to search [e.g. libc]')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def search(type, hex, string, executable, writable, value, mapping):
    # Adjust pointer sizes to the local architecture
    if type == 'pointer':
        type = {
            4: 'dword',
            8: 'qword'
        }[pwndbg.arch.ptrsize]

    if hex:
        value = codecs.decode(value, 'hex')

    # Convert to an integer if needed, and pack to bytes
    if type not in ('string', 'bytes'):
        value = pwndbg.commands.fix_int(value)
        fmt = {
            'little': '<',
            'big': '>'
        }[pwndbg.arch.endian] + {
            'byte': 'B',
            'short': 'H',
            'dword': 'L',
            'qword': 'Q'
        }[type]

        value = struct.pack(fmt, value)
    
    # Null-terminate strings
    elif type == 'string':
        value += '\x00'

    # Perform the search
    print_search(value, mapping=mapping, executable=executable, writable=writable)
