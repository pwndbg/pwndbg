#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import List


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
    debug = "PWNDBG_LLDB_DEBUG" in os.environ

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

    # Run our REPL until the user decides to leave.
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [filename]", file=sys.stderr)
        sys.exit(1)

    target = None
    if len(sys.argv) == 2:
        target = sys.argv[1]

    from pwndbg.dbg.lldb.repl import PwndbgController
    from pwndbg.dbg.lldb.repl import run as run_repl

    if debug:
        print("[-] Launcher: Entering Pwndbg CLI")

    def drive(startup: List[str] | None):
        async def drive(c: PwndbgController):
            if startup is not None:
                for line in startup:
                    await c.execute(line)

            while True:
                await c.interactive()

        return drive

    run_repl(drive([f"target create '{target}'"] if target else None), debug=debug)

    # Dispose of our debugger and terminate LLDB.
    lldb.SBDebugger.Destroy(debugger)
    lldb.SBDebugger.Terminate()
