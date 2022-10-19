import pwndbg.commands
from pwndbg.commands.misc import list_and_filter_commands

STACK_COMMANDS = [
    ("canary", "Print out the current stack canary."),
    ("context", "Print out the current register, instruction, and stack context."),
    ("down", "Select and print stack frame called by this one."),
    ("retaddr", "Print out the stack addresses that contain return addresses."),
    ("stack", "dereferences on stack data with specified count and offset."),
    ("up", "Select and print stack frame that called this one."),
]


def test_list_and_filter_commands_filter():
    for cmd in STACK_COMMANDS:
        assert cmd in list_and_filter_commands("stack")


def test_list_and_filter_commands_full_list():
    all_commands = list_and_filter_commands("", pwndbg_cmds=True, shell_cmds=True)

    def get_doc(c):
        return c.__doc__.strip().splitlines()[0] if c.__doc__ else None

    cmd_name_docs = [(c.__name__, get_doc(c)) for c in pwndbg.commands.commands]
    cmd_name_docs.sort()

    assert all_commands == cmd_name_docs


def test_list_and_filter_commands_shell():
    all_commands = list_and_filter_commands("", pwndbg_cmds=False, shell_cmds=True)

    def get_doc(c):
        return c.__doc__.strip().splitlines()[0] if c.__doc__ else None

    cmd_name_docs = [(c.__name__, get_doc(c)) for c in pwndbg.commands.commands if c.shell]
    cmd_name_docs.sort()

    assert all_commands == cmd_name_docs


def test_list_and_filter_commands_pwndbg_cmds():
    all_commands = list_and_filter_commands("", pwndbg_cmds=True, shell_cmds=False)

    def get_doc(c):
        return c.__doc__.strip().splitlines()[0] if c.__doc__ else None

    cmd_name_docs = [(c.__name__, get_doc(c)) for c in pwndbg.commands.commands if not c.shell]
    cmd_name_docs.sort()

    assert all_commands == cmd_name_docs
