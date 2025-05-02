from __future__ import annotations

import argparse
import re
from typing import Any
from typing import Dict

import pwndbg.aglib.dynamic
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
import pwndbg.color.message as message
import pwndbg.dbg
import pwndbg.gdblib.got
from pwndbg.commands import CommandCategory


def columns(rows, colors=None) -> None:
    """
    Print data formatted into distinct columns.
    """
    if len(rows) == 0:
        # Nothing to print.
        return

    col_max = [0] * len(rows[0])
    for i in range(len(rows)):
        if len(rows[i]) == 0:
            continue
        for j in range(len(col_max)):
            if len(rows[i][j]) > col_max[j]:
                col_max[j] = len(rows[i][j])

    for i in range(len(rows)):
        if len(rows[i]) == 0:
            print()
            continue

        for j in range(len(col_max)):
            color = colors[j] if colors is not None else lambda x: x
            print(f"{color(rows[i][j].ljust(col_max[j]))} ", end="")
        print()


parser = argparse.ArgumentParser(
    description="Controls GOT tracking",
)
subparsers = parser.add_subparsers(
    required=True, description="Used to disable and query information about the tracker"
)

# Subcommand that enables the tracker.
enable = subparsers.add_parser("enable", help="Enable GOT parsing")
enable.set_defaults(mode="enable")

# Subcommand that disables the tracker.
disable = subparsers.add_parser("disable", help="Disable GOT tracking")
disable.set_defaults(mode="disable")

# Subcommand that produces a report.
report = subparsers.add_parser("info", help="Give an overview of the GOT tracker")
report.add_argument(
    "-s",
    "--so-name",
    type=str,
    dest="soname",
    default=".*",
    help="Selects objects whose names matche the given expression",
)
report.add_argument(
    "-w",
    "--writable",
    dest="writable",
    action="store_true",
    help="Only show functions whose GOT entry is in a writable region of memory",
)
report.add_argument(
    "-f",
    "--function-name",
    type=str,
    dest="fnname",
    default=".*",
    help="Selects functions whose names match the given expression",
)
report.set_defaults(mode="report")

# Subcommand that queries for information about a specific tracker.
status = subparsers.add_parser(
    "query", help="Queries detailed tracking information about a single entry in the GOT"
)
status.add_argument(
    "address",
    type=str,
    help="The address of the GOT entry being tracked",
)
status.set_defaults(mode="status")


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX, command_name="track-got")
@pwndbg.commands.OnlyWhenRunning
def track_got(mode=None, soname=None, writable=False, fnname=None, address=None):
    if mode == "enable":
        # Enable the tracker.
        if pwndbg.gdblib.got.GOT_TRACKING:
            print("GOT tracking is already enabled. Did you mean to use a flag?")
            return
        pwndbg.gdblib.got.enable_got_call_tracking()
    elif mode == "disable":
        # Disable the tracker.
        if not pwndbg.gdblib.got.GOT_TRACKING:
            print("GOT tracking is already disabled. Did you mean to enable it with `track-got`?")
            return
        pwndbg.gdblib.got.disable_got_call_tracking()
    elif mode == "report":
        # Delegate to the report function.
        got_report(soname=soname, writable=writable, fnname=fnname)
    elif mode == "status":
        # Delegate to the status function.
        got_tracking_status(address=address)
    else:
        raise AssertionError(f"track-got must never have invalid mode '{mode}'. this is a bug")


def got_report(soname=".*", writable=False, fnname=".*") -> None:
    """
    Prints out a report of the current status of the GOT tracker.
    """
    if not pwndbg.gdblib.got.GOT_TRACKING:
        print(message.error("GOT call tracking is not enabled"))
        return

    soname = re.compile(soname)
    fnname = re.compile(fnname)

    print(
        f"Showing {'writable' if writable else 'all'} GOT function entries and how many times they were called."
    )
    print()

    per_object: Dict[Any, Any] = {}
    for _, (tracker, patcher) in pwndbg.gdblib.got.all_tracked_entries():
        objname = tracker.link_map_entry.name()
        if objname == b"":
            objname = pwndbg.aglib.proc.exe
        else:
            objname = pwndbg.gdblib.got.display_name(objname)

        # Filter out objects we're not interested in.
        if soname.match(objname) is None:
            continue

        if objname not in per_object:
            per_object[objname] = []
        per_object[objname].append((tracker, patcher))

    for objname, trackers in per_object.items():
        print(f"Calls from {objname}:")
        rows = [["Address in GOT", "Function Address", "Symbol", "Call Count"]]
        for tracker, patcher in trackers:
            # If requested, filter out entries that are not in a writable
            # portion of memory.
            if writable and not pwndbg.aglib.vmmap.find(patcher.entry).write:
                continue

            dynamic = tracker.dynamic_section
            sym_index = tracker.relocation_fn(tracker.relocation_index, "r_sym")
            sym_name = dynamic.symtab_read(sym_index, "st_name")
            sym_name = pwndbg.gdblib.got.display_name(dynamic.string(sym_name))

            # Filter out symbols we're not interested in.
            if fnname.match(sym_name) is None:
                continue

            if sym_name == "":
                sym_name = "<Empty>"

            hits = tracker.total_hits
            hits = f"{hits} hit{'s' if hits != 1 else ''}"
            rows.append([f"{patcher.entry:#x}", f"{tracker.target:#x}", sym_name, hits])
        columns(rows)
        print()


def got_tracking_status(address) -> None:
    """
    Prints out information about a single GOT tracking entry.
    """
    if not pwndbg.gdblib.got.GOT_TRACKING:
        print(message.error("GOT call tracking is not enabled"))
        return

    try:
        address = int(address, 0)
    except ValueError as e:
        print(message.error(f"Invalid address {address}: {e}"))
        return

    result = pwndbg.gdblib.got.tracked_entry_by_address(address)
    if result is None:
        print(message.error(f"No entry at address {address:#x}"))
        print("Hint: This command expects the address of the entry in the GOT. So, consider")
        print("using the address from the 'Address in GOT' column of the `track-got info`")
        print("command.")
        return

    tracker, _ = result

    dynamic = tracker.dynamic_section
    sym_index = tracker.relocation_fn(tracker.relocation_index, "r_sym")
    raw_sym_name = dynamic.symtab_read(sym_index, "st_name")
    sym_name = pwndbg.gdblib.got.display_name(dynamic.string(raw_sym_name))

    if sym_name == "":
        sym_name = "<Empty>"

    objname = tracker.link_map_entry.name()
    if objname == b"":
        objname = pwndbg.aglib.proc.exe
    else:
        objname = pwndbg.gdblib.got.display_name(objname)

    print(f"Tracking details for {sym_name}")
    print()
    print(f"Dynamic object name: {objname}")
    print(f"Jump target address: {tracker.target:#x}")
    print(f"GOT entry address:   {address:#x}")
    print(f"Relocation index:    {tracker.relocation_index}")
    print(f"Symbol index:        {sym_index}")
    print()

    callers = sorted(tracker.hits.items(), key=lambda x: x[1])
    for stack, hits in callers:
        print(f"Called {hits} times from stack:")
        for entry in stack:
            print(f"    - {entry:#x} ", end="")
            symname = pwndbg.aglib.symbol.resolve_addr(entry)
            if symname != "":
                print(f"<{symname}>", end="")
            print()
        print()
