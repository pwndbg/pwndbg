from __future__ import annotations

import gdb

import pwndbg
import pwndbg.commands


def test_consistent_help():
    """
    Tests that the help printed by gdb (via `help cmd`) is
    the exact same as the help printed by argparse (via `cmd -h`).
    """

    for cmd in pwndbg.commands.commands:
        name = cmd.command_name
        gdb_out = gdb.execute(f"help {name}", to_string=True)
        argparse_out = gdb.execute(f"{name} -h", to_string=True)

        if cmd.subcommand_names:
            # `help <main>` adds a hint to access subcommand information
            # we test if the remaining part is correct
            hint_header_line = f"\nHint: Use `{cmd.command_name} <subcmd> --help` if you want to see subcommand information"
            assert hint_header_line in gdb_out
            gdb_out = gdb_out[: gdb_out.index(hint_header_line)]

        # I would rather not strip, but gdb is inconsistent between versions.
        assert gdb_out.rstrip() == argparse_out.rstrip()
