from __future__ import annotations

import cProfile
import glob
import locale
import os
import site
import sys
import time
import warnings
from glob import glob
from os import environ
from os import path

_profiler = cProfile.Profile()
warnings.simplefilter("default", UnicodeWarning)

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


# warn if the user has different encoding than utf-8
encoding = locale.getpreferredencoding()

if encoding != "UTF-8":
    enc_warning_msg = """******
    Your encoding ({}) is different than UTF-8. pwndbg might now work properly.
    You might try launching GDB with:
        LC_CTYPE=C.UTF-8 gdb

    If that does not work, make sure that en_US.UTF-8 is uncommented in /etc/locale.gen and that you called `locale-gen` command.
    ******
    """.format(encoding)

    warnings.warn(enc_warning_msg, UnicodeWarning)

environ["PWNLIB_NOTERM"] = "1"

import pwndbg  # noqa: F401
import pwndbg.profiling

pwndbg.profiling.init(_profiler, _start_time)
if environ.get("PWNDBG_PROFILE") == "1":
    pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
    pwndbg.profiling.profiler.start()
