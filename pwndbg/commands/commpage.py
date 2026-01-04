from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

import pwndbg
import pwndbg.aglib.commpage
import pwndbg.commands
from pwndbg.commands import CommandCategory


def pretty_bytes(data: bytes) -> str:
    if not data:
        return "b''"

    if len(set(data)) == 1 and len(data) > 1:
        return f"b'\\x{data[0]:02x}' <repeats {len(data)} times>"

    return repr(data)


parser = argparse.ArgumentParser(description="Dumps all values from the macOS commpage.")
parser.add_argument("-v", "--verbose", action="store_true", help="Print detailed information.")


@pwndbg.commands.Command(parser, category=CommandCategory.DARWIN)
def commpage(verbose: bool = False):
    table = Table()

    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Address", style="magenta", no_wrap=True)
    table.add_column("Type", style="magenta", no_wrap=True)
    table.add_column("Value", style="green", overflow="fold")
    if verbose:
        table.add_column("Description", style="yellow", overflow="fold")

    for comm in pwndbg.aglib.commpage.get_commpage_fields():
        val = comm.unpack()
        style = None
        if comm.is_undocumented():
            style = "red"
        if comm.is_unused():
            style = "yellow"

        if isinstance(val, bytes):
            val = pretty_bytes(val)

        rows = [comm.name, hex(comm.real_addr()), comm.ctype, str(val)]
        if verbose:
            rows.append(comm.desc)
        table.add_row(*rows, style=style)

    Console().print(table)
