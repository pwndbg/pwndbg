#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command to print the virtual memory map a la /proc/self/maps.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import functools

import gdb
import six

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.compat
import pwndbg.vmmap


def map_type(s):
    gdbval_or_str = pwndbg.commands.sloppy_gdb_parse(s)

    # returns a module filter
    if isinstance(gdbval_or_str, six.string_types):
        module_name = gdbval_or_str
        return lambda page: module_name in page.objfile

    # returns an address filter
    elif isinstance(gdbval_or_str, six.integer_types + (gdb.Value,)):
        addr = gdbval_or_str
        return lambda page: addr in page

    else:
        raise argparse.ArgumentTypeError('Unknown vmmap argument type.')

parser = argparse.ArgumentParser()
parser.description = 'Print the virtual memory map, or the specific mapping for the provided address / module name.'
parser.add_argument('map', type=map_type, nargs='?', default=None,
                    help='Address or module name.')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def vmmap(map=None):
    print(map)
    pages = list(filter(map, pwndbg.vmmap.get()))

    if not pages:
        print('There are no mappings for specified address or module.')
        return

    print(M.legend())
    for page in pages:
        print(M.get(page.vaddr, text=str(page)))
