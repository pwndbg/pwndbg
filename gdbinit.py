from __future__ import annotations

import cProfile
import hashlib
import os
import site
import subprocess
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

    poetry_lock_file = os.path.join(directory, "poetry.lock")
    poetry_lock_hash_file = os.path.join(venv_path, "poetry.lock.hash")

    if os.path.exists(poetry_lock_hash_file):
        # Compare hashes
        with open(poetry_lock_hash_file, "r") as f:
            saved_hash = f.read().strip()
        with open(poetry_lock_file, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        if saved_hash == current_hash:
            # Hashes match, no need to install dependencies
            sys.exit(0)
    else:
        dev_marker_file = os.path.join(venv_path, "devMarker")
        if os.path.exists(dev_marker_file):
            command = ["poetry", "install", "-with", "dev"]
        else:
            command = ["poetry", "install"]

        # Run the command
        subprocess.run(command, check=True)

        # Compute hash of poetry.lock and save it
        with open(poetry_lock_file, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        with open(poetry_lock_hash_file, "w") as f:
            f.write(current_hash)

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

# Force UTF-8 encoding (to_string=True to skip output appearing to the user)
gdb.execute("set charset UTF-8", to_string=True)

environ["PWNLIB_NOTERM"] = "1"

import pwndbg  # noqa: F401
import pwndbg.profiling

pwndbg.profiling.init(_profiler, _start_time)
if environ.get("PWNDBG_PROFILE") == "1":
    pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
    pwndbg.profiling.profiler.start()
