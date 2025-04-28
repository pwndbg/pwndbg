from __future__ import annotations

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


def test_list_and_filter_commands_full_list():
    all_commands = list_and_filter_commands("")

    def get_doc(c):
        return c.description.splitlines()[0]

    cmd_name_docs = [
        (c.command_name, c.aliases, c.category, get_doc(c)) for c in pwndbg.commands.commands
    ]
    cmd_name_docs.sort()

    assert all_commands == cmd_name_docs
