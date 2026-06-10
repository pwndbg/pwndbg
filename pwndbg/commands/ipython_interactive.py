"""
Command to start an interactive IPython prompt.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager

import gdb

import pwndbg.commands
import pwndbg.lib.stdio
from pwndbg.color import message
from pwndbg.commands import CommandCategory


@contextmanager
def switch_to_ipython_env() -> Iterator[None]:
    saved_excepthook = sys.excepthook
    try:
        saved_ps = sys.ps1, sys.ps2
    except AttributeError:
        saved_ps = None
    yield
    # Restore Python's default `ps1`, `ps2`, and `excepthook`
    # to ensure proper behavior of the GDB repl.
    if saved_ps is not None:
        sys.ps1, sys.ps2 = saved_ps
    else:
        del sys.ps1
        del sys.ps2
    sys.excepthook = saved_excepthook


@pwndbg.commands.Command("Start an interactive IPython prompt.", category=CommandCategory.MISC)
def ipi() -> None:
    with switch_to_ipython_env():
        # Use `gdb.execute` to embed IPython into GDB's variable scope
        try:
            gdb.execute("pi import IPython")
        except gdb.error:
            print(
                message.warn(
                    "Cannot import IPython.\n"
                    "You need to install IPython if you want to use this command.\n"
                    "Maybe you can try `pip install ipython` first."
                )
            )
            return
        code4ipython = """import jedi
import pwn
from pwndbg.aglib.ipi_helpers import get_ipi_namespace, get_banner
jedi.Interpreter._allow_descriptor_getattr_default = False
# Get pwndbg helpers and merge with globals
_ipi_helpers = get_ipi_namespace()
_user_ns = {**globals(), **_ipi_helpers}
# Print banner
print(get_banner(), end="")
IPython.embed(colors='neutral',banner1='',confirm_exit=False,simple_prompt=False, user_ns=_user_ns)
"""
        gdb.execute(f"py\n{code4ipython}")
