#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Hexdump implementation, ~= stolen from pwntools.
"""
from __future__ import print_function
from __future__ import unicode_literals

import copy
import string

import pwndbg.color.hexdump as H
import pwndbg.config


color_scheme = None
printable = None

def groupby(array, count, fill=None):
    array = copy.copy(array)
    while fill and len(array) % count:
        array.append(fill)
    for i in range(0, len(array), count):
        yield array[i:i+count]

@pwndbg.config.Trigger([H.config_normal, H.config_zero, H.config_special, H.config_printable])
def load_color_scheme():
    global color_scheme, printable
    #
    # We want to colorize the hex characters and only print out
    # printable values on the righ hand side.
    #
    color_scheme = {i:H.normal("%02x" % i) for i in range(256)}
    printable = {i:H.normal('.') for i in range(256)}

    for c in bytearray((string.ascii_letters + string.digits + string.punctuation).encode('utf-8', 'ignore')):
        color_scheme[c] = H.printable("%02x" % c)
        printable[c] = H.printable("%s" % chr(c))

    for c in bytearray(b'\x00'):
        color_scheme[c] = H.zero("%02x" % c)
        printable[c] = H.zero('.')

    for c in bytearray(b'\xff\x7f\x80'):
        color_scheme[c] = H.special("%02x" % c)
        printable[c] = H.special('.')

    color_scheme[-1] = '  '
    printable[-1] = ' '

def hexdump(data, address = 0, width = 16, skip = True):
    if not color_scheme or not printable:
        load_color_scheme()
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
            hexline.append(H.offset("+%04x " % (i*width)))

        hexline.append(H.offset("%#08x  " % (base + (i*width))))

        for group in groupby(line, 4):
            for char in group:
                hexline.append(color_scheme[char])
                hexline.append(' ')
            hexline.append(' ')

        hexline.append(H.separator('|'))
        for group in groupby(line, 4):
            for char in group:
                hexline.append(printable[char])
            hexline.append(H.separator('|'))


        yield(''.join(hexline))

    hexline = []

    if address:
        hexline.append(H.offset("+%04x " % len(data)))

    hexline.append(H.offset("%#08x  " % (base + len(data))))

    yield ''.join(hexline)
