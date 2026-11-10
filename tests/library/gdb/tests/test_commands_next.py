from __future__ import annotations

import gdb
import pytest

NEXT_COMMANDS = (
    "pc",
    "nextcall",
    "nextjmp",
    "nextproginstr",
    "nextret",
    "nextsyscall",
    "stepret",
    "stepsyscall",
)


@pytest.mark.parametrize("command", NEXT_COMMANDS)
def test_next_commands_binary_not_running(command):
    out = gdb.execute(command, to_string=True)
    assert out == f"{command}: The program is not being run.\n"
