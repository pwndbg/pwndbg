"""
Command to start an interactive IPython prompt.
"""
import sys
from contextlib import contextmanager

import gdb

import pwndbg.commands


@contextmanager
def switch_to_ipython_env():
    """We need to change stdout/stderr to the default ones, otherwise we can't use tab or autocomplete"""
    # Save GDB's stdout and stderr
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr
    # Use Python's default stdout and stderr
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    yield
    # Restore GDB's stdout and stderr
    sys.stdout = saved_stdout
    sys.stderr = saved_stderr
    # Restore Python's default ps1 and ps2 for GDB's `pi` command
    sys.ps1 = ">>> "
    sys.ps2 = "... "


@pwndbg.commands.ArgparsedCommand("Start an interactive IPython prompt.")
def ipi():
    with switch_to_ipython_env():
        # Use `gdb.execute` to embed IPython into GDB's variable scope
        code4ipython = """import IPython
import jedi
import pwn
jedi.Interpreter._allow_descriptor_getattr_default = False
IPython.embed(colors='neutral',banner1='',confirm_exit=False,simple_prompt=False)
""".strip().replace(
            "\n", ";"
        )
        gdb.execute(f"pi {code4ipython}")
