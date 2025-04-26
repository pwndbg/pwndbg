from __future__ import annotations

import os

import gdb
import pytest

import tests
from pwndbg.commands import command_names

BINARY = tests.binaries.get("heap_bins.out")

# TODO: See if we can reduce the number of commands we need to skip
disallowed_commands = {
    # requires user input
    "ipi",
    # takes too long
    "nextproginstr",
}

filtered_commands = command_names - disallowed_commands

# TODO: Figure out why these are being thrown and then remove this
allowed_exceptions = [
    "Cannot access memory at address",
    "Cannot insert breakpoint",
    "Warning:",
    "The program is not being run",
]

# Only run on CI, unless the user requests this with the RUN_FLAKY environment variable
running_on_ci = os.getenv("GITHUB_ACTIONS")
run_flaky = os.getenv("RUN_FLAKY")

should_skip_test = not running_on_ci and not run_flaky
if should_skip_test:
    # The test name will look like "test_commands[*]" if the test is skipped
    filtered_commands = set("*")


@pytest.mark.parametrize("name", filtered_commands)
@pytest.mark.skipif(condition=should_skip_test, reason="flaky test")
@pytest.mark.xfail(reason="flaky test")
def test_commands(start_binary, name):
    print("Running command", name)
    start_binary(BINARY)
    try:
        gdb.execute(name)
    except gdb.error as e:
        ignore = False
        for ex in allowed_exceptions:
            if ex in str(e):
                ignore = True
                print("Ignoring exception in command", name)
                break

        if not ignore:
            raise e
