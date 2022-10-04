"""
Command to start an interactive IPython prompt.
"""
import sys
from contextlib import contextmanager

import gdb

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.lib.stdio


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


@pwndbg.commands.ArgparsedCommand("Start an interactive IPython prompt.")
def ipi():
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
IPython.embed(colors='neutral',banner1='',confirm_exit=False,simple_prompt=False, user_ns=globals())
"""
        gdb.execute(f"py\n{code4ipython}")
