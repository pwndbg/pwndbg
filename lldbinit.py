from __future__ import annotations

import cProfile
import os
import site
import sys
import time
from glob import glob
from os import environ
from os import path

_profiler = cProfile.Profile()

_start_time = None
if environ.get("PWNDBG_PROFILE") == "1":
    _start_time = time.time()
    _profiler.enable()

# Get virtualenv's site-packages path
venv_path = os.environ.get("PWNDBG_VENV_PATH")
if venv_path == "PWNDBG_PLEASE_SKIP_VENV" or path.exists(path.dirname(__file__) + "/.skip-venv"):
    pass
else:
    directory, file = path.split(__file__)
    directory = path.expanduser(directory)
    directory = path.abspath(directory)

    if not venv_path:
        venv_path = os.path.join(directory, ".venv")

    if not os.path.exists(venv_path):
        print(f"Cannot find Pwndbg virtualenv directory: {venv_path}: please re-run setup.sh")
        sys.exit(1)

    site_pkgs_path = glob(os.path.join(venv_path, "lib/*/site-packages"))[0]

    # add virtualenv's site-packages to sys.path and run .pth files
    site.addsitedir(site_pkgs_path)

    # remove existing, system-level site-packages from sys.path
    for site_packages in site.getsitepackages():
        if site_packages in sys.path:
            sys.path.remove(site_packages)

    # Set virtualenv's bin path (needed for utility tools like ropper, pwntools etc)
    bin_path = os.path.join(venv_path, "bin")
    os.environ["PATH"] = bin_path + os.pathsep + os.environ.get("PATH", "")

    # Add pwndbg directory to sys.path so it can be imported
    sys.path.insert(0, directory)

    # Push virtualenv's site-packages to the front
    sys.path.remove(site_pkgs_path)
    sys.path.insert(1, site_pkgs_path)

environ["PWNLIB_NOTERM"] = "1"

import pwndbg  # noqa: F401
import pwndbg.dbg.lldb
import pwndbg.profiling

pwndbg.dbg = pwndbg.dbg_mod.lldb.LLDB()


class Test:
    def __init__(self, debugger, _):
        pass

    def __call__(self, debugger, command, exe_context, result):
        print(f"{debugger}, {command}, {exe_context}, {result}")


def __lldb_init_module(debugger, _):
    """
    Actually handles the setup bits for LLDB.

    LLDB, unlike GDB, exposes the bits we're interested in through object
    instances, and we are only passed the instance for the interactive debugger
    through this function.
    """
    import pwndbg.dbg

    pwndbg.dbg.setup(debugger)
    import pwndbg.lldblib

    pwndbg.lldblib.register_class_as_cmd(debugger, "test", Test)

    pwndbg.profiling.init(_profiler, _start_time)
    if environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
        pwndbg.profiling.profiler.start()
