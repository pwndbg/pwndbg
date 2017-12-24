#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A few helpers for making things print pretty-like.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import fcntl
import os
import struct
import sys
import termios

import pwndbg.arch
import pwndbg.color.context as C
import pwndbg.color.theme as theme
import pwndbg.config as config

theme.Parameter('banner-separator', '─', 'repeated banner separator character')

def banner(title):
    title = title.upper()
    _height, width = get_window_size()
    width -= 2
    return C.banner(("[{:%s^%ss}]" % (config.banner_separator, width)).format(title))

def addrsz(address):
    address = int(address) & pwndbg.arch.ptrmask
    return "%{}x".format(2*pwndbg.arch.ptrsize) % address

def get_window_size():
    fallback = (int(os.environ.get('LINES', 20)), int(os.environ.get('COLUMNS', 80)))
    if not sys.stdin.isatty:
        return fallback
    try:
        # get terminal size and force ret buffer len of 4 bytes for safe unpacking by passing equally long arg
        rows, cols = struct.unpack('hh', fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, '1234'))
    except:
        rows, cols = fallback
    return rows, cols
