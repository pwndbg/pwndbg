from __future__ import annotations

import os
import sys

import pytest

PWNDBG_ROOT = os.environ.get("TEST_PWNDBG_ROOT")
TESTS_PATH = os.environ.get("TESTS_PATH")

if TESTS_PATH is None:
    print("'TESTS_PATH' environment variable not set. Failed to collect tests.")
    sys.exit(1)

host_home = f"{PWNDBG_ROOT}/tests/"
if host_home not in sys.path:
    sys.path.append(host_home)


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
    sys.exit(1)


print("Listing collected tests:")
for nodeid in collector.collected:
    print("Test:", nodeid)

# easy way to exit GDB session
sys.exit(0)
