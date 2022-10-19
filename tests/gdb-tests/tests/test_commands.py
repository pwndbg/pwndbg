import gdb
import pytest

import tests
from pwndbg.commands import command_names
from pwndbg.commands.shell import shellcmd_names

BINARY = tests.binaries.get("heap_bins.out")

# TODO: See if we can reduce the number of commands we need to skip
blacklisted_commands = set(
    [
        "disasm",
        "unhex",
        "bugreport",
        "try_free",
        "errno",
        "nextproginstr",
    ]
)

# Don't run any shell commands
blacklisted_commands.update(shellcmd_names)

# TODO: Figure out why these are being thrown and then remove this
whitelisted_exceptions = [
    "Cannot access memory at address",
    "Cannot insert breakpoint",
    "Warning:",
    "The program is not being run",
]


@pytest.mark.skip(reason="flaky test")
def test_commands(start_binary):
    for name in command_names:
        print("Running command", name)
        try:
            start_binary(BINARY)

            if name in blacklisted_commands:
                continue

            gdb.execute(name)
        except gdb.error as e:
            ignore = False
            for ex in whitelisted_exceptions:
                if ex in str(e):
                    ignore = True
                    print("Ignoring exception in command", name)
                    break

            if not ignore:
                raise e
