import cProfile
import glob
import locale
import os
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

directory, file = path.split(__file__)
directory = path.expanduser(directory)
directory = path.abspath(directory)

# Get virtualenv's site-packages path
venv_path = os.environ.get("PWNDBG_VENV_PATH")
if not venv_path:
    venv_path = os.path.join(directory, ".venv")

site_pkgs_path = glob(os.path.join(venv_path, "lib/*/site-packages"))[0]

# Set virtualenv's bin path (needed for utility tools like ropper, pwntools etc)
bin_path = os.path.join(venv_path, "bin")
os.environ["PATH"] = bin_path + os.path.sep + os.environ.get("PATH")

# Add gdb-pt-dump directory to sys.path so it can be imported
gdbpt = path.join(directory, "gdb-pt-dump")
sys.path.append(directory)
sys.path.append(site_pkgs_path)
sys.path.append(gdbpt)

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
