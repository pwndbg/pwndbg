"""
This file should consist of global test fixtures.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
import pytest


@pytest.fixture
def entry_binary():
    """
    Returns function that launches given binary with 'entry' command
    """
    def _entry_binary(name):
        gdb.execute('file ./tests/binaries/' + name)
        gdb.execute('entry')

    return _entry_binary
