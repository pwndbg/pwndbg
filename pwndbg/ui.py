#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A few helpers for making things print pretty-like.
"""
from __future__ import print_function
from __future__ import unicode_literals

import fcntl
import struct
import sys
import termios

import pwndbg.arch


def banner(title):
    title = title.upper()
    try:
        _height, width = struct.unpack('hh', fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, '1234'))
    except:
        width = 80
    width -= 2
    return ("[{:-^%ss}]" % width).format(title)

def addrsz(address):
    address = int(address) & pwndbg.arch.ptrmask
    return "%{}x".format(2*pwndbg.arch.ptrsize) % address
