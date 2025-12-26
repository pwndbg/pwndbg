"""
Runs a few useful commands which are available under "info".
"""

from __future__ import annotations

import gdb

import pwndbg.lib.cache

# TODO: Add symbol, threads, dll, program


@pwndbg.lib.cache.cache_until("exit")
def proc_mappings() -> str:
    try:
        return gdb.execute("info proc mappings", to_string=True)
    except gdb.error:
        return ""


@pwndbg.lib.cache.cache_until("exit")
def auxv() -> str:
    try:
        return gdb.execute("info auxv", to_string=True)
    except gdb.error:
        return ""


@pwndbg.lib.cache.cache_until("stop")
def files() -> str:
    try:
        return gdb.execute("info files", to_string=True)
    except gdb.error:
        return ""
