"""
This file should consist of global test fixtures.
"""

from __future__ import annotations

import os

import gdb
import pytest

_start_binary_called = False


@pytest.fixture
def start_binary():
    """
    Returns function that launches given binary with 'starti' command
    """

    def _start_binary(path, *args):
        os.environ["PWNDBG_IN_TEST"] = "1"
        gdb.execute("file " + path)
        gdb.execute("set exception-verbose on")
        gdb.execute("set width 80")
        gdb.execute("set context-reserve-lines never")
        os.environ["COLUMNS"] = "80"
        gdb.execute("starti " + " ".join(args))

        global _start_binary_called
        # if _start_binary_called:
        #     raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary
