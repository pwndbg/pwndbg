from __future__ import annotations

import cProfile
import locale
import os
import site
import sys
import time
from os import environ
from os import path

_profiler = cProfile.Profile()

_start_time = None
if environ.get("PWNDBG_PROFILE") == "1":
    _start_time = time.time()
    _profiler.enable()

# Get virtualenv's site-packages path
venv_path = os.environ.get("PWNDBG_VENV_PATH")
if venv_path == "PWNDBG_PLEASE_SKIP_VENV":
    pass
else:
    directory, file = path.split(__file__)
    directory = path.expanduser(directory)
    directory = path.abspath(directory)

    if not venv_path:
        venv_path = os.path.join(directory, ".venv")

    activate_this = os.path.join(venv_path, "bin/activate_this.py")

    if not os.path.exists(activate_this):
        print(f"Cannot find Pwndbg virtualenv directory: {venv_path}: please re-run setup.sh")
        sys.exit(1)

    exec(open(activate_this).read(), {"__file__": activate_this})

    # remove existing, system-level site-packages from sys.path
    for site_packages in site.getsitepackages():
        if site_packages in sys.path:
            sys.path.remove(site_packages)

    # Add gdb-pt-dump directory to sys.path so it can be imported
    gdbpt = path.join(directory, "gdb-pt-dump")
    sys.path.insert(0, directory)
    sys.path.insert(1, gdbpt)

# warn if the user has different encoding than utf-8
encoding = locale.getpreferredencoding()

if encoding != "UTF-8":
    print("******")
    print(f"Your encoding ({encoding}) is different than UTF-8. pwndbg might not work properly.")
    print("You might try launching GDB with:")
    print("    LC_CTYPE=C.UTF-8 gdb")
    print(
        "If that does not work, make sure that en_US.UTF-8 is uncommented in /etc/locale.gen and that you called `locale-gen` command"
    )
    print("******")

environ["PWNLIB_NOTERM"] = "1"

import pwndbg  # noqa: F401
import pwndbg.profiling

pwndbg.profiling.init(_profiler, _start_time)
if environ.get("PWNDBG_PROFILE") == "1":
    pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
    pwndbg.profiling.profiler.start()
