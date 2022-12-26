import gdb
from pyannotate_runtime import collect_types

from pwndbg.commands import command_names
from pwndbg.commands.shell import pwncmd_names
from pwndbg.commands.shell import shellcmd_names

disallowed_commands = set(
    [
        # requires user input
        "ipi",
        # takes too long
        "nextproginstr",
    ]
)

# Don't run any shell commands
disallowed_commands.update(shellcmd_names)
disallowed_commands.update(pwncmd_names)

filtered_commands = command_names - disallowed_commands

allowed_exceptions = [
    "Cannot access memory at address",
    "Cannot insert breakpoint",
    "Warning:",
    "The program is not being run",
]


def test_commands():
    for name in filtered_commands:
        print("Running command", name)
        try:
            gdb.execute(name)
        except gdb.error as e:
            pass
    collect_types.dump_stats("stats.json")
