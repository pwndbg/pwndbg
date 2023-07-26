from __future__ import annotations

import pytest

import pwndbg.commands
from pwndbg.commands.misc import list_and_filter_commands

STACK_COMMANDS = [
    ("canary", [], "Stack", "Print out the current stack canary."),
    (
        "context",
        ["ctx"],
        "Context",
        "Print out the current register, instruction, and stack context.",
    ),
    ("down", [], "Misc", "Select and print stack frame called by this one."),
    ("retaddr", [], "Stack", "Print out the stack addresses that contain return addresses."),
    ("stack", [], "Stack", "Dereferences on stack data with specified count and offset."),
    ("up", [], "Misc", "Select and print stack frame that called this one."),
]


def test_list_and_filter_commands_filter():
    for cmd in STACK_COMMANDS:
        assert cmd in list_and_filter_commands("stack")


@pytest.mark.parametrize("pwndbg_cmds,shell_cmds", [(True, True), (False, True), (True, False)])
def test_list_and_filter_commands_full_list(pwndbg_cmds, shell_cmds):
    all_commands = list_and_filter_commands("", pwndbg_cmds=pwndbg_cmds, shell_cmds=shell_cmds)

    def get_doc(c):
        return c.__doc__.strip().splitlines()[0] if c.__doc__ else None

    commands = []
    if pwndbg_cmds:
        commands.extend([c for c in pwndbg.commands.commands if not c.is_alias and not c.shell])
    if shell_cmds:
        commands.extend([c for c in pwndbg.commands.commands if not c.is_alias and c.shell])

    cmd_name_docs = [(c.__name__, c.aliases, c.category, get_doc(c)) for c in commands]
    cmd_name_docs.sort()

    assert all_commands == cmd_name_docs
