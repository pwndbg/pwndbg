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


parser = argparse.ArgumentParser()
parser.description = 'Print the virtual memory map, or the specific mapping for the provided address / module name.'
parser.add_argument('map', type=pwndbg.commands.sloppy_gdb_parse, nargs='?', default=None,
                    help='Address or module name.')


def address_filter(addr, page):
    return addr in page


def module_filter(module_name, page):
    return module_name in page.objfile


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def vmmap(map=None):
    pages_filter = None

    if isinstance(map, six.string_types):
        pages_filter = functools.partial(module_filter, map)
    elif isinstance(map, six.integer_types + (gdb.Value,)):
        pages_filter = functools.partial(address_filter, map)

    pages = list(filter(pages_filter, pwndbg.vmmap.get()))

    print(M.legend())
    for page in pages:
        print(M.get(page.vaddr, text=str(page)))
