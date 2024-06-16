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
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            file_hash.update(chunk)
    return file_hash.hexdigest()


def run_poetry_install(dev=False):
    command = ["poetry", "install"]
    if dev:
        command.extend(("--with", "dev"))
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def update_deps(file_path):
    poetry_lock_path = os.path.join(os.path.dirname(file_path), "poetry.lock")
    poetry_lock_hash_path = os.path.join(venv_path, "poetry.lock.hash")
    dev_marker_path = os.path.join(venv_path, "dev.marker")

    current_hash = calculate_hash(poetry_lock_path)
    stored_hash = None
    if os.path.exists(poetry_lock_hash_path):
        with open(poetry_lock_hash_path, "r") as f:
            stored_hash = f.read().strip()

    # checks if dev.marker exists
    dev_mode = os.path.exists(dev_marker_path)

    # if hashes don't match, run the appropriate command based on dev.marker file
    if current_hash != stored_hash:
        run_poetry_install(dev=dev_mode)
        with open(poetry_lock_hash_path, "w") as f:
            f.write(current_hash)


if venv_path != "PWNDBG_PLEASE_SKIP_VENV" and not path.exists(
    path.dirname(__file__) + "/.skip-venv"
):
    directory, file = path.split(__file__)
    directory = path.expanduser(directory)
    directory = path.abspath(directory)

    if not venv_path:
        venv_path = os.path.join(directory, ".venv")

    if not os.path.exists(venv_path):
        print(f"Cannot find Pwndbg virtualenv directory: {venv_path}: please re-run setup.sh")
        sys.exit(1)

    update_deps(__file__)

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
