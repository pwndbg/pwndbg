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


def calculate_hash(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()


def run_poetry_install(dev=False):
    command = ["poetry", "install"]
    if dev:
        command = ["poetry", "install", "--with", "dev"]
    subprocess.run(command, check=True)


PWNDBG_VENV_PATH = os.getenv("PWNDBG_VENV_PATH")
POETRY_LOCK_PATH = os.path.join(os.path.dirname(__file__), "poetry.lock")
POETRY_LOCK_HASH_PATH = os.path.join(PWNDBG_VENV_PATH, "poetry.lock.hash")
DEV_MARKER_PATH = os.path.join(PWNDBG_VENV_PATH, "dev.marker")

# verify virtual environment path exists
os.makedirs(PWNDBG_VENV_PATH, exist_ok=True)

current_hash = calculate_hash(POETRY_LOCK_PATH)
if os.path.exists(POETRY_LOCK_HASH_PATH):
    with open(POETRY_LOCK_HASH_PATH, "r") as f:
        stored_hash = f.read().strip()
else:
    stored_hash = None

dev_mode = os.path.exists(DEV_MARKER_PATH)  # checks if dev.marker exists

# if hashes doesn't match, run the appropriate command based dev.marker file
if current_hash != stored_hash:
    run_poetry_install(dev=dev_mode)
    with open(POETRY_LOCK_HASH_PATH, "w") as f:
        f.write(current_hash)

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

# Force UTF-8 encoding (to_string=True to skip output appearing to the user)
gdb.execute("set charset UTF-8", to_string=True)

environ["PWNLIB_NOTERM"] = "1"

import pwndbg  # noqa: F401
import pwndbg.profiling

pwndbg.profiling.init(_profiler, _start_time)
if environ.get("PWNDBG_PROFILE") == "1":
    pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
    pwndbg.profiling.profiler.start()
