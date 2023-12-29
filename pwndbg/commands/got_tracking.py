from __future__ import annotations

import argparse

import pwndbg.color.message as message
import pwndbg.gdblib.dynamic
import pwndbg.gdblib.got
import pwndbg.gdblib.proc
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Enables the GOT call tracking",
)


@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.LINUX, command_name="enable-got-tracking"
)
@pwndbg.commands.OnlyWhenRunning
def enable_got_tracking():
    pwndbg.gdblib.got.enable_got_call_tracking()


@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.LINUX, command_name="disable-got-tracking"
)
@pwndbg.commands.OnlyWhenRunning
def disable_got_tracking():
    pwndbg.gdblib.got.disable_got_call_tracking()


def try_decode(name):
    """
    Ideally, we'd like to display all of the names of the symbols as text, but
    there is really nothing stopping symbol names from being stored in some
    fairly wacky encoding or really from having names that aren't text at all.

    We should try our best to turn whatever the symbol name is into text, but
    not so much that non-text entries or entries in unknown encodings become
    unrecognizable.
    """
    try:
        return name.decode("ascii")
    except TypeError:
        return name


@pwndbg.commands.ArgparsedCommand(
    parser, category=CommandCategory.LINUX, command_name="got-call-status"
)
@pwndbg.commands.OnlyWhenRunning
def got_call_status():
    if not pwndbg.gdblib.got.GOT_TRACKING:
        print(message.error("GOT call tracking is not enabled"))
        return

    per_object = {}
    for _, (tracker, _) in pwndbg.gdblib.got.all_tracked_entries():
        objname = tracker.link_map_entry.name()
        if objname not in per_object:
            per_object[objname] = []
        per_object[objname].append(tracker)

    for objname, trackers in per_object.items():
        if objname == b"":
            objname = pwndbg.gdblib.proc.exe
        else:
            objanme = try_decode(objname)

        print(f"GOT entry points for {objname}:")
        for tracker in trackers:
            dynamic = tracker.dynamic_segment
            sym_index = tracker.relocation_fn(tracker.relocation_index, "r_sym")
            sym_name = dynamic.symtab_read(sym_index, "st_name")
            sym_name = try_decode(dynamic.string(sym_name))

            if sym_name == "":
                sym_name = "<Empty>"

            print(f"    {tracker.target:#x} - {sym_name} - {tracker.total_hits} hits")
