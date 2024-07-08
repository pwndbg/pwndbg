from __future__ import annotations

import os
import sys

import pytest

TESTS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tests/system")


class CollectTestFunctionNames:
    """See https://github.com/pytest-dev/pytest/issues/2039#issuecomment-257753269"""

    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            self.collected.append(item.nodeid)


collector = CollectTestFunctionNames()
rv = pytest.main(["--collect-only", TESTS_PATH], plugins=[collector])

if rv == pytest.ExitCode.INTERRUPTED:
    print("Failed to collect all tests, perhaps there is a syntax error in one of test files?")
    sys.stdout.flush()
    os._exit(1)


print("Listing collected tests:")
for nodeid in collector.collected:
    print("Test:", nodeid)

# easy way to exit GDB session
sys.exit(0)
