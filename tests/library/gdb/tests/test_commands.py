from __future__ import annotations

import os

import gdb
import pytest

from pwndbg.commands import command_names

from . import get_binary

BINARY = get_binary("heap_bins.native.out")

# TODO: See if we can reduce the number of commands we need to skip
disallowed_commands = {
    # requires user input
    "ipi",
    # Already tested by other tests & takes too long
    "pc",
    "nextcall",
    "nextjump",
    "nextproginstr",
    "nextret",
    "nextsyscall",
    "stepret",
    "stepsyscall",
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


def test_only_when_running_checked_before_argparse() -> None:
    """
    Regression test for #1462.

    @OnlyWhenRunning commands must short-circuit with the standard
    "The program is not being run." message before argparse evaluates
    arguments. Otherwise default args like "$sp"/"$rip" or symbol-style
    args leak cryptic resolution errors when there's no inferior.
    """
    expected = "The program is not being run."

    # `address` defaults to "$sp" - argparse runs string defaults through
    # type=int, which used to fail with "No registers." here.
    out = gdb.execute("telescope", to_string=True)
    assert f"telescope: {expected}" in out, out

    # Explicit register reference - same failure mode.
    out = gdb.execute("telescope $rip", to_string=True)
    assert f"telescope: {expected}" in out, out

    # Symbol-style args that fail to resolve without a symbol table.
    out = gdb.execute("xor a a a", to_string=True)
    assert f"xor: {expected}" in out, out

    # --help must still work without a running program.
    out = gdb.execute("telescope --help", to_string=True)
    assert expected not in out
    assert "Recursively dereferences pointers" in out
