"""
Runs a few useful commands which are available under "info".
"""

import re
from typing import Optional

import gdb

import pwndbg.lib.memoize

# TODO: Add symbol, threads, dll, program


@pwndbg.lib.memoize.reset_on_exit
def proc_mappings():
    try:
        return gdb.execute("info proc mappings", to_string=True)
    except gdb.error:
        return ""


@pwndbg.lib.memoize.reset_on_exit
def auxv():
    try:
        return gdb.execute("info auxv", to_string=True)
    except gdb.error:
        return ""


@pwndbg.lib.memoize.reset_on_stop
def files():
    try:
        return gdb.execute("info files", to_string=True)
    except gdb.error:
        return ""


def target():
    try:
        return gdb.execute("info target", to_string=True)
    except gdb.error:
        return ""


def sharedlibrary():
    try:
        return gdb.execute("info sharedlibrary", to_string=True)
    except gdb.error:
        return ""


def address(symbol: str) -> Optional[int]:
    try:
        res = gdb.execute(f"info address {symbol}", to_string=True)
        return int(re.search("0x[0-9a-fA-F]+", res).group(), 0)
    except gdb.error:
        return None
