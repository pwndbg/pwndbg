"""
This file should consist of global test fixtures.
"""

import gdb
import pytest

_start_binary_called = False


@pytest.fixture
def start_binary():
    """
    Returns function that launches given binary with 'starti' command
    """

    def _start_binary(path, *args):
        gdb.execute("file " + path)
        gdb.execute("set exception-verbose on")
        gdb.execute("starti " + " ".join(args))

        global _start_binary_called
        # if _start_binary_called:
        #     raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary
