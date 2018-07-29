from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import sys

import pytest


TESTS_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'tests'
)


class CollectTestFunctionNames:
    """See https://github.com/pytest-dev/pytest/issues/2039#issuecomment-257753269"""
    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            self.collected.append(item.nodeid)


collector = CollectTestFunctionNames()
pytest.main(['--collect-only', TESTS_PATH], plugins=[collector])

print('Listing collected tests:')
for nodeid in collector.collected:
    print('Test:', nodeid)

# easy way to exit GDB session
sys.exit(0)
