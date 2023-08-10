import argparse

import pwndbg.chain
import pwndbg.commands
import pwndbg.gdblib.heap_tracking

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Enables the heap tracker.

The heap tracker is a module that tracks usage of the GLibc heap and looks for
user errors such as double frees and use after frees.

Currently, the following errors can be detected:
    - Use After Free

Use `disable-heap-tracker` to disable it.
""",
)

parser.add_argument(
    "-b",
    "--hardware-breakpoints",
    dest="use_hardware_breakpoints",
    type=bool,
    default=False,
    help="Force the tracker to use hardware breakpoints.",
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="enable-heap-tracker")
def enable_tracker(use_hardware_breakpoints=False) -> None:
    pwndbg.gdblib.heap_tracking.install()


parser = argparse.ArgumentParser(description="Disables the heap tracker.")


@pwndbg.commands.ArgparsedCommand(parser, command_name="disable-heap-tracker")
def disable_tracker() -> None:
    pwndbg.gdblib.heap_tracking.uninstall()
