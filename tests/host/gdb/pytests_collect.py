from __future__ import annotations

import contextlib
import os
import sys

import pytest
from _pytest.skipping import Skip

TESTS_PATH = os.environ.get("TESTS_PATH")

if TESTS_PATH is None:
    print("'TESTS_PATH' environment variable not set. Failed to collect tests.")
    sys.exit(1)


class CollectTestFunctionNames:
    """See https://github.com/pytest-dev/pytest/issues/2039#issuecomment-257753269"""

    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            skip = None
            mark = item.get_closest_marker("skip")
            # skipif runs first in pytest and may depend on run time, so GDB handles those.
            if mark and not item.get_closest_marker("skipif"):
                with contextlib.suppress(TypeError):  # a bad mark still errors when the test runs
                    skip = Skip(*mark.args, **mark.kwargs)
            self.collected.append((item.nodeid, skip))


collector = CollectTestFunctionNames()
rv = pytest.main(["--collect-only", TESTS_PATH], plugins=[collector])

if rv == pytest.ExitCode.INTERRUPTED:
    print("Failed to collect all tests, perhaps there is a syntax error in one of test files?")
    sys.exit(1)


print("Listing collected tests:")
for nodeid, skip in collector.collected:
    print("Test:", nodeid)
    # The host skips these without starting GDB; stderr keeps reasons out of the test-name scan.
    if skip and isinstance(skip.reason, str) and skip.reason.isprintable():
        print(f"Skip: {nodeid}\t{skip.reason}", file=sys.stderr)

# easy way to exit GDB session
sys.exit(0)
