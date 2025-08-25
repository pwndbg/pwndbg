"""
Command to start an interactive IPython prompt.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager

import gdb

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.lib.stdio
from pwndbg.commands import CommandCategory


@contextmanager
def switch_to_ipython_env():
    """We need to change stdout/stderr to the default ones, otherwise we can't use tab or autocomplete"""
    # Save GDB's excepthook
    saved_excepthook = sys.excepthook
    # Switch to default stdout/stderr
    with pwndbg.lib.stdio.stdio:
        yield
    # Restore Python's default ps1, ps2, and excepthook for GDB's `pi` command
    sys.ps1 = ">>> "
    sys.ps2 = "... "
    sys.excepthook = saved_excepthook


@pwndbg.commands.Command("Start an interactive IPython prompt.", category=CommandCategory.MISC)
def ipi() -> None:
    with switch_to_ipython_env():
        # Use `gdb.execute` to embed IPython into GDB's variable scope
        try:
            gdb.execute("pi import IPython")
        except gdb.error:
            print(
                M.warn(
                    "Cannot import IPython.\n"
                    "You need to install IPython if you want to use this command.\n"
                    "Maybe you can try `pip install ipython` first."
                )
            )
            return
        code4ipython = """import jedi
import pwn
jedi.Interpreter._allow_descriptor_getattr_default = False

from pwndbg.aglib.memory import read, write
import pwndbg.aglib.vmmap as vmmap
from pwndbg.commands.hexdump import hexdump
from pwndbg.commands.search import search

def r(addr, length): return read(int(addr,16), length)

def w(addr, data): return write(int(addr,16), data)

def vv(): return vmmap.get()

def h(addr, length): hexdump(int(addr,16), length)

def s(type="bytes", asmbp=False, hex=False, executable=False, writable=False,
      step=None, limit=None, aligned=None, value="", mapping_name=None,
      save=None, next=False, trunc_out=False):
    search(type, asmbp, hex, executable, writable, step,
           limit, aligned, value, mapping_name, save, next, trunc_out)

IPython.embed(colors='neutral',banner1='',confirm_exit=False,simple_prompt=False, user_ns=globals())
"""
        M.hint("Shortcuts: r(), w(), vv(), h(), s()")
        gdb.execute(f"py\n{code4ipython}")
