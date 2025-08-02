from __future__ import annotations

from . import pwndbg_test

STACK_COMMANDS = [
    ("canary", [], "Stack", "Print out the current stack canary."),
    # The aliases 'do' and 'dow' were added to support the help consistency test.
    ("retaddr", [], "Stack", "Print out the stack addresses that contain return addresses."),
    ("stack", [], "Stack", "Dereferences on stack data with specified count and offset."),
]


@pwndbg_test
async def test_list_and_filter_commands_filter(_ctrl: Controller):
    from pwndbg.commands.misc import list_and_filter_commands

    for cmd in STACK_COMMANDS:
        assert cmd in list_and_filter_commands("stack")


@pwndbg_test
async def test_list_and_filter_commands_full_list(_ctrl: Controller):
    import pwndbg.commands
    from pwndbg.commands.misc import list_and_filter_commands

    all_commands = list_and_filter_commands("")

    def get_doc(c):
        return c.description.splitlines()[0]

    cmd_name_docs = [
        (c.command_name, c.aliases, c.category, get_doc(c)) for c in pwndbg.commands.commands
    ]
    cmd_name_docs.sort()

    assert all_commands == cmd_name_docs
