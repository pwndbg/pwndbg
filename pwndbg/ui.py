"""
A few helpers for making things print pretty-like.
"""

from __future__ import annotations

import fcntl
import os
import struct
import sys
import termios

#import gdb

import pwndbg.color.context as C
#import pwndbg.gdblib.arch
from pwndbg.color import ljust_colored
from pwndbg.color import message
from pwndbg.color import rjust_colored
from pwndbg.color import strip
from pwndbg.color import theme
from pwndbg.config import config

theme.add_param("banner-separator", "─", "repeated banner separator character")
theme.add_param("banner-title-surrounding-left", "[ ", "banner title surrounding char (left side)")
theme.add_param(
    "banner-title-surrounding-right", " ]", "banner title surrounding char (right side)"
)
title_position = theme.add_param("banner-title-position", "center", "banner title position")


@config.trigger(title_position)
def check_title_position() -> None:
    valid_values = ["center", "left", "right"]
    if title_position not in valid_values:
        print(
            message.warn(
                f"Invalid title position: {title_position}, must be one of: {', '.join(valid_values)}"
            )
        )
        title_position.revert_default()


def banner(title, target=sys.stdin, width=None, extra=""):
    title = title.upper()
    if width is None:  # auto width. In case of stdout, it's better to use stdin (b/c GdbOutputFile)
        _height, width = get_window_size(target=target if target != sys.stdout else sys.stdin)
    if title:
        title = "{}{}{}{}".format(
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


def addrsz(address) -> str:
    return "%#16x"
    address = int(address) & pwndbg.gdblib.arch.ptrmask
    return f"%#{2 * pwndbg.gdblib.arch.ptrsize}x" % address


def get_window_size(target=sys.stdin):
    fallback = (int(os.environ.get("LINES", 20)), int(os.environ.get("COLUMNS", 80)))
    if not target.isatty():
        return fallback
    rows, cols = get_cmd_window_size()
    if rows is not None and cols is not None:
        return rows, cols
    try:
        # get terminal size and force ret buffer len of 4 bytes for safe unpacking by passing equally long arg
        rows, cols = struct.unpack("hh", fcntl.ioctl(target.fileno(), termios.TIOCGWINSZ, b"1234"))
    except Exception:
        rows, cols = fallback
    return rows, cols


def get_cmd_window_size():
    """Get the size of the command window in TUI mode which could be different than the terminal window width \
    with horizontal split "tui new-layout hsrc { -horizontal src 1 cmd 1 } 1".

    Possible output of "info win" in TUI mode:
    (gdb) info win
    Name       Lines Columns Focus
    src           77     104 (has focus)
    cmd           77     105

    Output of "info win" in non-TUI mode:
    (gdb) info win
    The TUI is not active."""
    return 80,24
    try:
        info_out = gdb.execute("info win", to_string=True).split()
    except gdb.error:
        # Return None if the command is not compiled into GDB
        # (gdb.error: Undefined info command: "win".  Try "help info")
        return None, None
    if "cmd" not in info_out:
        # if TUI is not enabled, info win will output "The TUI is not active."
        return None, None
    # parse cmd window size from the output of "info win"
    cmd_win_index = info_out.index("cmd")
    if len(info_out) <= cmd_win_index + 2:
        return None, None
    elif not info_out[cmd_win_index + 1].isdigit() and not info_out[cmd_win_index + 2].isdigit():
        return None, None
    else:
        return int(info_out[cmd_win_index + 1]), int(info_out[cmd_win_index + 2])
