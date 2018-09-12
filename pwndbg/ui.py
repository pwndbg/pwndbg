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
from pwndbg import config
from pwndbg.color import ljust_colored
from pwndbg.color import message
from pwndbg.color import rjust_colored
from pwndbg.color import strip
from pwndbg.color import theme

theme.Parameter('banner-separator', '─', 'repeated banner separator character')
theme.Parameter('banner-title-surrounding-left', '[ ', 'banner title surrounding char (left side)')
theme.Parameter('banner-title-surrounding-right', ' ]', 'banner title surrounding char (right side)')
title_position = theme.Parameter('banner-title-position', 'center', 'banner title position')


@pwndbg.config.Trigger([title_position])
def check_title_position():
    valid_values = ['center', 'left', 'right']
    if title_position not in valid_values:
        print(message.warn('Invalid title position: %s, must be one of: %s' %
              (title_position, ', '.join(valid_values))))
        title_position.revert_default()


def banner(title, make_upper=True, trunc_after_idx=-1):
    """
    Renders a banner.

    Arguments:
        title(str): banner title string
        make_upper(bool): whether the title be uppercase
        trunc_after_idx(int): if the value is bigger than 0,
            and the title is too long, it will be truncated
            on the left side but after the provided index
    """
    if make_upper:
        title = title.upper()

    _height, width = get_window_size()

    if trunc_after_idx > 0:
        banner_len = len(config.banner_title_surrounding_left) + len(config.banner_title_surrounding_right)
        size_to_trunc = len(title) - (width - banner_len - 3)

        if size_to_trunc > 0:
            title = title[:trunc_after_idx] + '~' + title[trunc_after_idx+size_to_trunc:]

    title = '%s%s%s' % (config.banner_title_surrounding_left, C.banner_title(title), config.banner_title_surrounding_right)
    if 'left' == title_position:
        banner = ljust_colored(title, width, config.banner_separator)
    elif 'right' == title_position:
        banner = rjust_colored(title, width, config.banner_separator)
    else:
        banner = rjust_colored(title, (width + len(strip(title))) // 2, config.banner_separator)
        banner = ljust_colored(banner, width, config.banner_separator)

    return C.banner(banner)

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
