"""
This file should consist of global test fixtures.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
import pytest

_start_binary_called = False


@pytest.fixture
def start_binary():
    """
    Returns function that launches given binary with 'start' command
    """
    def _start_binary(path):
        gdb.execute('file ' + path)
        gdb.execute('start')

        global _start_binary_called
        if _start_binary_called:
            raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary
