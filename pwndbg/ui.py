"""
A few helpers for making things print pretty-like.
"""

from __future__ import annotations

import os
import sys

import pwndbg.color.context as C
import pwndbg.dbg
from pwndbg import config
from pwndbg.color import ljust_colored
from pwndbg.color import rjust_colored
from pwndbg.color import strip
from pwndbg.color import theme

theme.add_param("banner-separator", "─", "repeated banner separator character")
theme.add_param("banner-title-surrounding-left", "[ ", "banner title surrounding char (left side)")
theme.add_param(
    "banner-title-surrounding-right", " ]", "banner title surrounding char (right side)"
)
title_position = theme.add_param(
    "banner-title-position",
    "center",
    "banner title position",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["center", "left", "right"],
)


def banner(title, target=sys.stdout, width=None, extra=""):
    title = title.upper()
    if width is None:
        _height, width = get_window_size(target)
    if title:
        title = "{}{}{}{}".format(
            config.banner_title_surrounding_left,
            C.banner_title(title),
            extra,
            config.banner_title_surrounding_right,
        )
    if "left" == title_position:
        banner = ljust_colored(title, width, str(config.banner_separator))
    elif "right" == title_position:
        banner = rjust_colored(title, width, str(config.banner_separator))
    else:
        banner = rjust_colored(
            title, (width + len(strip(title))) // 2, str(config.banner_separator)
        )
        banner = ljust_colored(banner, width, str(config.banner_separator))
    return C.banner(banner)


def addrsz(address) -> str:
    return pwndbg.dbg.addrsz(address)


def get_window_size(target=sys.stdout):
    fallback = (int(os.environ.get("LINES", 20)), int(os.environ.get("COLUMNS", 80)))
    if not target.isatty():
        return fallback
    if os.environ.get("PWNDBG_IN_TEST") is not None:
        return fallback

    if target in (sys.stdout, sys.stdin):
        # We can ask the debugger for the window size
        rows, cols = get_cmd_window_size()
        if rows is not None and cols is not None:
            return rows, cols

    try:
        term = os.get_terminal_size(target.fileno())
        return term.lines, term.columns
    except Exception:
        pass

    return fallback


def get_cmd_window_size():
    return pwndbg.dbg.get_cmd_window_size()
