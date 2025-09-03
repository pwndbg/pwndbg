#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from typing import Any
from typing import Callable
from typing import Coroutine
from typing import List
from typing import Tuple


def find_lldb_version() -> Tuple[int, ...]:
    """
    Parses the version string given to us by the LLDB executable.
    """
    lldb = subprocess.run(["lldb", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if lldb.returncode != 0:
        print(f"Could not find the LLDB Python Path: {lldb.stderr!r}", file=sys.stderr)
        sys.exit(1)
    output = lldb.stdout.decode("utf-8").strip()
    output = re.sub("[^0-9.]", "", output)

    return tuple(int(component) for component in output.split("."))


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


def launch(
    controller: Callable[..., Coroutine[Any, Any, None]],
    *args,
    debug: bool = False,
) -> None:
    """
    Launch Pwndbg with the given controller.
    """

    if sys.platform == "linux" and "LLDB_DEBUGSERVER_PATH" not in os.environ:
        os.environ["LLDB_DEBUGSERVER_PATH"] = shutil.which("lldb-server")

    # Older LLDB versions crash newer versions of CPython on import, so check
    # for it, and stop early with an error message.
    #
    # See https://github.com/llvm/llvm-project/issues/70453
    lldb_version = find_lldb_version()

    if debug:
        print(f"[-] Launcher: LLDB version {'.'.join(map(str, lldb_version))}")

    if sys.version_info.minor >= 12 and lldb_version[0] <= 18:
        print("LLDB 18 and earlier is incompatible with Python 3.12 and later", file=sys.stderr)
        sys.exit(1)

    try:
        import lldb
    except ImportError:
        # Find the path for the LLDB Python bindings.
        path = find_lldb_python_path()
        sys.path.append(path)
        if debug:
            print(f"[-] Launcher: LLDB Python path: {path}")
        import lldb

    # Start up LLDB and create a new debugger object.
    lldb.SBDebugger.Initialize()
    debugger = lldb.SBDebugger.Create()

    from pwndbginit import lldbinit
    from pwndbginit import pwndbglldbhandler

    debugger.HandleCommand(f"command script import {pwndbglldbhandler.__file__}")

    # Initialize the debugger, proper.
    if debug:
        print("[-] Launcher: Initializing Pwndbg")
    lldbinit.main(debugger, lldb_version, debug=debug)

    from pwndbg.dbg.lldb.repl import run as run_repl

    if debug:
        print("[-] Launcher: Entering Pwndbg CLI")

    run_repl(controller, *args, debug=debug)

    # Dispose of our debugger and terminate LLDB.
    lldb.SBDebugger.Destroy(debugger)
    lldb.SBDebugger.Terminate()


def get_venv_bin_path():
    bin_dir = "Scripts" if os.name == "nt" else "bin"
    return os.path.join(sys.prefix, bin_dir)


def prepend_venv_bin_to_path():
    # Set virtualenv's bin path (needed for utility tools like ropper, pwntools etc)
    venv_bin = get_venv_bin_path()
    path_elements = os.environ.get("PATH", "").split(os.pathsep)
    if venv_bin in path_elements:
        return

    path_elements.insert(0, venv_bin)
    os.environ["PATH"] = os.pathsep.join(path_elements)


def main() -> None:
    """
    Entry point for the pwndbg-lldb command line tool.
    """
    prepend_venv_bin_to_path()

    # Parse the arguments we were given.
    parser = argparse.ArgumentParser(prog="pwndbg-lldb")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug output")
    parser.add_argument("target", nargs="?")
    parser_attach = parser.add_mutually_exclusive_group()
    parser_attach.add_argument(
        "-n", "--attach-name", help="Tells the debugger to attach to a process with the given name."
    )
    parser_attach.add_argument(
        "-p", "--attach-pid", help="Tells the debugger to attach to a process with the given pid."
    )
    parser.add_argument(
        "-w",
        "--wait-for",
        action="store_true",
        help="Tells the debugger to wait for a process with the given pid or name to launch before attaching.",
    )

    args = parser.parse_args()
    debug = args.verbose

    # Prepare the startup commands based on those arguments.
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
            print("warn: '--wait-for' has no effect when used with '--attach-pid'")

        startup.append(f'process attach --pid "{args.attach_pid}"')
    else:
        if args.wait_for:
            # Ideally, we would have `ArgumentParser` do this for us, but
            # nesting argument groups has been deprecated since Python 3.11, and
            # the deprecation message suggests it was never even supported in
            # the first place :/
            print(
                "error: '--wait-for' must be used in combination with either '--attach-name' or '--attach-pid'"
            )
            parser.print_usage()
            sys.exit(1)

    if (args.attach_pid is not None or args.attach_name is not None) and args.target:
        print(
            "warn: have both a target and an attach request, your target may be overwritten on attach"
        )

    def drive(startup: List[str] | None):
        async def drive(c):
            from pwndbg.dbg.lldb.repl import PwndbgController

            assert isinstance(c, PwndbgController)

            if startup is not None:
                for line in startup:
                    await c.execute(line)

            while True:
                await c.interactive()

        return drive

    # Launch Pwndbg in interactive mode.
    launch(drive(startup), debug=debug)


if __name__ == "__main__":
    main()
