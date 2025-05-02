from __future__ import annotations

import argparse
import shutil

import pwndbg.aglib.onegadget
import pwndbg.aglib.proc
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.glibc
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""
Find gadgets which single-handedly give code execution.

Uses the onegadget tool by david942j.
""",
)

parser.add_argument("--show-unsat", help="Show unsatisfiable gadgets.", action="store_true")
parser.add_argument("--no-unknown", help="Do not show unknown gadgets.", action="store_true")
parser.add_argument("-v", "--verbose", help="Show verbose output.", action="store_true")


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "i386", "aarch64"])
@pwndbg.commands.OnlyWhenRunning
def onegadget(show_unsat: bool = False, no_unknown: bool = False, verbose: bool = False) -> None:
    if not shutil.which("one_gadget"):
        print(M.error("Could not find one_gadget. Please ensure it's installed and in $PATH."))
        return

    path = pwndbg.glibc.get_libc_filename_from_info_sharedlibrary()
    if not path:
        print(M.error("Could not find libc. Please ensure it's loaded."))
        return
    print(f"Using libc: {M.hint(path)}")
    print()

    gadgets_count = pwndbg.aglib.onegadget.find_gadgets(show_unsat, no_unknown, verbose)
    for result, count in gadgets_count.items():
        print(f"Found {M.hint(count)} {result} gadgets.")
    if not gadgets_count[pwndbg.aglib.onegadget.SAT] and not show_unsat:
        print(
            M.warn(
                "No valid gadgets found, you might want to run with --show-unsat again to check unsatisfiable gadgets.\n"
                "To see why they are unsatisfiable, you might want to run with -v or --verbose."
            )
        )
