from __future__ import annotations

import gdb

import pwndbg


def test_consistent_help():
    """
    Tests that the help printed by gdb (via `help cmd`) is
    the exact same as the help printed by argparse (via `cmd -h`).
    """

    for cmd in pwndbg.commands.commands:
        name = cmd.command_name
        gdb_out = gdb.execute(f"help {name}", to_string=True)
        argparse_out = gdb.execute(f"{name} -h", to_string=True)

        assert gdb_out == argparse_out
