"""
A few helpers for making things print pretty-like.
"""

import fcntl
import os
import struct
import sys
import termios

import pwndbg.color.context as C
import pwndbg.gdblib.arch
from pwndbg.color import ljust_colored
from pwndbg.color import message
from pwndbg.color import rjust_colored
from pwndbg.color import strip
from pwndbg.color import theme
from pwndbg.gdblib import config

theme.add_param("banner-separator", "─", "repeated banner separator character")
theme.add_param("banner-title-surrounding-left", "[ ", "banner title surrounding char (left side)")
theme.add_param(
    "banner-title-surrounding-right", " ]", "banner title surrounding char (right side)"
)
title_position = theme.add_param("banner-title-position", "center", "banner title position")


@config.trigger(title_position)
def check_title_position():
    valid_values = ["center", "left", "right"]
    if title_position not in valid_values:
        print(
            message.warn(
                "Invalid title position: %s, must be one of: %s"
                % (title_position, ", ".join(valid_values))
            )
        )
        title_position.revert_default()


def banner(title, target=sys.stdin, width=None, extra=""):
    title = title.upper()
    if width is None:  # auto width. In case of stdout, it's better to use stdin (b/c GdbOutputFile)
        _height, width = get_window_size(target=target if target != sys.stdout else sys.stdin)
    if title:
        title = "%s%s%s%s" % (
            config.banner_title_surrounding_left,
            C.banner_title(title),
            extra,
            config.banner_title_surrounding_right,
        )
    if "left" == title_position:
        banner = ljust_colored(title, width, config.banner_separator)
    elif "right" == title_position:
        banner = rjust_colored(title, width, config.banner_separator)
    else:
        banner = rjust_colored(title, (width + len(strip(title))) // 2, config.banner_separator)
        banner = ljust_colored(banner, width, config.banner_separator)
    return C.banner(banner)


def addrsz(address):
    address = int(address) & pwndbg.gdblib.arch.ptrmask
    return "%#{}x".format(2 * pwndbg.gdblib.arch.ptrsize) % address


def get_window_size(target=sys.stdin):
    fallback = (int(os.environ.get("LINES", 20)), int(os.environ.get("COLUMNS", 80)))
    if not target.isatty():
        return fallback
    try:
        # get terminal size and force ret buffer len of 4 bytes for safe unpacking by passing equally long arg
        rows, cols = struct.unpack("hh", fcntl.ioctl(target.fileno(), termios.TIOCGWINSZ, "1234"))
    except Exception:
        rows, cols = fallback
    return rows, cols
