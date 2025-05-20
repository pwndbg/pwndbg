from __future__ import annotations

import argparse

import pwndbg.chain
import pwndbg.commands
import pwndbg.gdblib.ptmalloc2_tracking
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""Manages the heap tracker.

The heap tracker is a module that tracks usage of the GLibc heap and looks for
user errors such as double frees and use after frees.

Currently, the following errors can be detected:
    - Use After Free
""",
)

subparsers = parser.add_subparsers(
    required=True, description="Used to enable, disable and query information about the tracker"
)

# Subcommand that enables the tracker.
enable = subparsers.add_parser("enable", help="Enable heap tracking")
enable.add_argument(
    "-b",
    "--hardware-breakpoints",
    dest="use_hardware_breakpoints",
    type=bool,
    default=False,
    help="Force the tracker to use hardware breakpoints.",
)
enable.set_defaults(mode="enable")

# Subcommand that disables the tracker.
disable = subparsers.add_parser("disable", help="Disable heap tracking")
disable.set_defaults(mode="disable")

# Subcommand that produces a report.
toggle_break = subparsers.add_parser(
    "toggle-break", help="Toggles whether possible UAF conditions will pause execution"
)
toggle_break.set_defaults(mode="toggle-break")


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX, command_name="track-heap")
@pwndbg.commands.OnlyWhenRunning
def track_heap(mode=None, use_hardware_breakpoints=False):
    if mode == "enable":
        # Enable the tracker.
        pwndbg.gdblib.ptmalloc2_tracking.install()
    elif mode == "disable":
        # Disable the tracker.
        pwndbg.gdblib.ptmalloc2_tracking.uninstall()
    elif mode == "toggle-break":
        # Delegate to the report function.
        pwndbg.gdblib.ptmalloc2_tracking.stop_on_error = (
            not pwndbg.gdblib.ptmalloc2_tracking.stop_on_error
        )
        if pwndbg.gdblib.ptmalloc2_tracking.stop_on_error:
            print("The program will stop when the heap tracker detects an error")
        else:
            print("The heap tracker will only print a message when it detects an error")
    else:
        raise AssertionError(f"track-heap must never have invalid mode '{mode}'. this is a bug")
