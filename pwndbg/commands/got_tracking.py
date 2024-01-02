from __future__ import annotations

import argparse
import re

import pwndbg.color.message as message
import pwndbg.gdblib.dynamic
import pwndbg.gdblib.got
import pwndbg.gdblib.proc
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Toggles the GOT call tracking",
)


@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.LINUX, command_name="toggle-got-tracking"
)
@pwndbg.commands.OnlyWhenRunning
def toggle_got_tracking():
    if not pwndbg.gdblib.got.GOT_TRACKING:
        pwndbg.gdblib.got.enable_got_call_tracking()
    else:
        pwndbg.gdblib.got.disable_got_call_tracking()

def columns(rows, colors=None):
    """
    Print data formatted into distinct columns.
    """
    if len(rows) == 0:
        # Nothing to print.
        return

    col_max = [0 for _ in range(len(rows[0]))]
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
    description="Displays an overview of the GOT tracking",
)
parser.add_argument(
    "-s",
    "--so-name",
    type=str,
    dest="soname",
    default=".*",
    help="Selects objects whose names matche the given expression",
)
parser.add_argument(
    "-w",
    "--writable",
    dest="writable",
    action="store_true",
    help="Only show functions whose GOT entry is in a writable region of memory"
)
parser.add_argument(
    "-f",
    "--function-name",
    type=str,
    dest="fnname",
    default=".*",
    help="Selects functions whose names match the given expression"
)

@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.LINUX, command_name="got-report"
)
@pwndbg.commands.OnlyWhenRunning
def got_report(soname=".*", writable=False, fnname=".*"):
    if not pwndbg.gdblib.got.GOT_TRACKING:
        print(message.error("GOT call tracking is not enabled"))
        return

    soname = re.compile(soname)
    fnname = re.compile(fnname)

    print(f"Showing {'writable' if writable else 'all'} GOT function entries and how many times they were called.")
    print()

    per_object = {}
    for _, (tracker, patcher) in pwndbg.gdblib.got.all_tracked_entries():
        objname = tracker.link_map_entry.name()
        if objname == b"":
            objname = pwndbg.gdblib.proc.exe
        else:
            objname = pwndbg.gdblib.got.display_name(objname)

        # Filter out objects we're not interested in.
        if soname.match(objname) is None:
            continue

        if objname not in per_object:
            per_object[objname] = []
        per_object[objname].append((tracker, patcher))

    rows = [["Objfile", "Address in GOT", "Function Address", "Symbol", "Call Count"]]

    for objname, trackers in per_object.items():
        for tracker, patcher in trackers:
            # If requested, filter out entries that are not in a writable
            # portion of memory.
            if writable and not pwndbg.gdblib.vmmap.find(patcher.entry).write:
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
            rows.append([objname, f"{tracker.target:#x}", f"{patcher.entry:#x}", sym_name, hits])
        rows.append([])

    columns(rows)

parser = argparse.ArgumentParser(
    description="Displays the tracking status of a GOT entry.",
)
parser.add_argument(
    "address",
    type=str,
    help="The address of the GOT entry being tracked",
)

@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.LINUX, command_name="got-tracking-status"
)
@pwndbg.commands.OnlyWhenRunning
def got_tracking_status(address):
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
        return

    tracker, patcher = result
    rows = []

    dynamic = tracker.dynamic_section
    sym_index = tracker.relocation_fn(tracker.relocation_index, "r_sym")
    raw_sym_name = dynamic.symtab_read(sym_index, "st_name")
    sym_name = pwndbg.gdblib.got.display_name(dynamic.string(raw_sym_name))

    if sym_name == "":
        sym_name = "<Empty>"

    objname = tracker.link_map_entry.name()
    if objname == b"":
        objname = pwndbg.gdblib.proc.exe
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
            symname = pwndbg.gdblib.symbol.get(entry)
            if symname != "":
                print(f"<{symname}>", end="")
            print()
        print()
