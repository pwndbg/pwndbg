#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Hexdump implementation, ~= stolen from pwntools.
"""
from __future__ import print_function
from __future__ import unicode_literals

import copy
import string

import pwndbg.color


def groupby(array, count, fill=None):
    array = copy.copy(array)
    while fill and len(array) % count:
        array.append(fill)
    for i in range(0, len(array), count):
        yield array[i:i+count]

#
# We want to colorize the hex characters
#
color_scheme = {i:pwndbg.color.normal("%02x" % i) for i in range(256)}

for c in bytearray((string.ascii_letters + string.digits + string.punctuation).encode('utf-8', 'ignore')):
    color_scheme[c] = pwndbg.color.bold("%02x" % c)

for c in bytearray(b'\x00\xff'):
    color_scheme[c] = pwndbg.color.red("%02x" % c)

for c in bytearray(b'\xff\x7f\x80'):
    color_scheme[c] = pwndbg.color.yellow("%02x" % c)

color_scheme[-1] = '  '

#
# Only print out printable values on the righ hand side
#
printable = {i:'.' for i in range(256)}
for c in bytearray((string.ascii_letters + string.digits + string.punctuation).encode('utf-8', 'ignore')):
    printable[c] = chr(c)

printable[-1] = ' '


def hexdump(data, address = 0, width = 16, skip = True):
    data = list(bytearray(data))
    base = address
    last_line = None
    skipping  = False
    for i, line in enumerate(groupby(data, width, -1)):
        if skip and line == last_line:
            if not skipping:
                skipping = True
                yield '...'
            continue
        else:
            skipping  = False
            last_line = line

        hexline = []

        if address:
            hexline.append("+%04x " % (i*width))

        hexline.append("%#08x  " % (base + (i*width)))

        for group in groupby(line, 4):
            for char in group:
                hexline.append(color_scheme[char])
                hexline.append(' ')
            hexline.append(' ')

        hexline.append('|')
        for group in groupby(line, 4):
            for char in group:
                hexline.append(printable[char])
            hexline.append('|')


        yield(''.join(hexline))

    hexline = []

    if address:
        hexline.append("+%04x " % len(data))

    hexline.append("%#08x  " % (base + len(data)))

    yield ''.join(hexline)
