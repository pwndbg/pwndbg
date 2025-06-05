#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import List

PARSER = argparse.ArgumentParser(prog="pwndbg-lldb")
PARSER.add_argument("-v", "--verbose", action="store_true", help="Enable debug output")
PARSER.add_argument("target", nargs="?")
parser_attach = PARSER.add_mutually_exclusive_group()
parser_attach.add_argument(
    "-n", "--attach-name", help="Tells the debugger to attach to a process with the given name."
)
parser_attach.add_argument(
    "-p", "--attach-pid", help="Tells the debugger to attach to a process with the given pid."
)
PARSER.add_argument(
    "-w",
    "--wait-for",
    action="store_true",
    help="Tells the debugger to wait for a process with the given pid or name to launch before attaching.",
)


def find_lldb_version() -> List[int]:
    """
    Parses the version string given to us by the LLDB executable.
    """
    lldb = subprocess.run(["lldb", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if lldb.returncode != 0:
        print(f"Could not find the LLDB Python Path: {lldb.stderr!r}", file=sys.stderr)
        sys.exit(1)
    output = lldb.stdout.decode("utf-8").strip()
    output = re.sub("[^0-9.]", "", output)

    return [int(component) for component in output.split(".")]


def find_lldb_python_path() -> str:
    """
    Finds the Python path pointed to by the LLDB executable.
    """
    lldb = subprocess.run(["lldb", "-P"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if lldb.returncode != 0:
        print(f"Could not find the LLDB Python Path: {lldb.stderr!r}", file=sys.stderr)
        sys.exit(1)

    folder = lldb.stdout.decode("utf-8").strip()
    if not os.path.exists(folder):
        print(f"Path pointed to by LLDB ('{folder}') does not exist", file=sys.stderr)
        sys.exit(1)

    return folder


if __name__ == "__main__":
    args = PARSER.parse_args()
    debug = args.verbose

    # Find the path for the LLDB Python bindings.
    path = find_lldb_python_path()
    sys.path.append(path)

    if debug:
        print(f"[-] Launcher: LLDB Python path: {path}")

    # Older LLDB versions crash newer versions of CPython on import, so check
    # for it, and stop early with an error message.
    #
    # See https://github.com/llvm/llvm-project/issues/70453
    lldb_version = find_lldb_version()

    if debug:
        print(f"[-] Launcher: LLDB version {lldb_version[0]}.{lldb_version[1]}")

    if sys.version_info.minor >= 12 and lldb_version[0] <= 18:
        print("LLDB 18 and earlier is incompatible with Python 3.12 and later", file=sys.stderr)
        sys.exit(1)

    # Start up LLDB and create a new debugger object.
    import lldb

    lldb.SBDebugger.Initialize()
    debugger = lldb.SBDebugger.Create()

    # Resolve the location of lldbinit.py based on the environment, if needed.
    lldbinit_dir = os.path.dirname(sys.argv[0])
    if "PWNDBG_LLDBINIT_DIR" in os.environ:
        lldbinit_dir = os.environ["PWNDBG_LLDBINIT_DIR"]
    lldbinit_dir = os.path.abspath(lldbinit_dir)
    lldbinit_path = os.path.join(lldbinit_dir, "lldbinit.py")

    if debug:
        print(f"[-] Launcher: Importing main LLDB module at '{lldbinit_path}'")

    if not os.path.exists(lldbinit_path):
        print(f"Could not find '{lldbinit_path}, please specify it with PWNDBG_LLDBINIT_DIR")
        sys.exit(1)

    if lldbinit_path not in sys.path:
        sys.path.append(lldbinit_dir)

    # Load the lldbinit module we just found.
    debugger.HandleCommand(f"command script import {lldbinit_path}")

    # Initialize the debugger, proper.
    import lldbinit

    if debug:
        print("[-] Launcher: Initializing Pwndbg")
    lldbinit.main(debugger, lldb_version[0], lldb_version[1], debug=debug)

    from pwndbg.dbg.lldb.repl import PwndbgController
    from pwndbg.dbg.lldb.repl import print_error
    from pwndbg.dbg.lldb.repl import print_warn
    from pwndbg.dbg.lldb.repl import run as run_repl

    if debug:
        print("[-] Launcher: Entering Pwndbg CLI")

    # Prepare the startup commands.
    startup = []
    if args.target:
        # DEVIATION: The LLDB CLI silently ignores any target information passed
        # to it when using either '--attach-name' or '--attach-pid', but Pwndbg
        # unconditionally uses it, with a warning.
        startup = [f"target create '{args.target}'"]

    if args.attach_name is not None:
        wait = "--waitfor" if args.wait_for else ""
        startup.append(f'process attach --name "{args.attach_name}" {wait}')
    elif args.attach_pid is not None:
        # DEVIATION: While the LLDB CLI accepts '--wait-for' in combination with
        # both '--attach-name' and '--attach-pid', it silently ignores it when
        # used with the latter. Pwndbg prints out a warning, instead.
        if args.wait_for:
            print_warn("'--wait-for' has no effect when used with '--attach-pid'")

        startup.append(f'process attach --pid "{args.attach_pid}"')
    else:
        if args.wait_for:
            # Ideally, we would have `ArgumentParser` do this for us, but
            # nesting argument groups has been deprecated since Python 3.11, and
            # the deprecation message suggests it was never even supported in
            # the first place :/
            print_error(
                "'--wait-for' must be used in combination with either '--attach-name' or '--attach-pid'"
            )
            PARSER.print_usage()
            sys.exit(1)

    if (args.attach_pid is not None or args.attach_name is not None) and args.target:
        print_warn(
            "have both a target and an attach request, your target may be overwritten on attach"
        )

    def drive(startup: List[str] | None):
        async def drive(c: PwndbgController):
            if startup is not None:
                for line in startup:
                    await c.execute(line)

            while True:
                await c.interactive()

        return drive

    run_repl(drive(startup), debug=debug)

    # Dispose of our debugger and terminate LLDB.
    lldb.SBDebugger.Destroy(debugger)
    lldb.SBDebugger.Terminate()
