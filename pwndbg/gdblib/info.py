"""
Runs a few useful commands which are available under "info".

We probably don't need this anymore.
"""

import gdb

import pwndbg.lib.memoize

# TODO: Add address, symbol, threads, dll, program


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
