from __future__ import annotations

import cProfile
import hashlib
import importlib.abc
import logging
import os
import shutil
import site
import subprocess
import sys
import time
import traceback
from glob import glob
from pathlib import Path
from typing import List
from typing import Tuple

import gdb


# Fix gdb readline bug: https://github.com/pwndbg/pwndbg/issues/2232#issuecomment-2542564965
class GdbRemoveReadlineFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "readline":
            raise ImportError("readline module disabled under GDB")
        return None


sys.meta_path.insert(0, GdbRemoveReadlineFinder())


def hash_file(file_path: str | Path) -> str:
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256()
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            file_hash.update(chunk)
    return file_hash.hexdigest()


def run_uv_install(
    binary_path: os.PathLike[str], src_root: Path, dev: bool = False
) -> Tuple[str, str, int]:
    command: List[str] = [str(binary_path), "sync", "--extra", "gdb"]
    if dev:
        command.extend(("--all-groups",))
    logging.debug(f"Updating deps with command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True, cwd=src_root)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def find_uv(venv_path: Path) -> Path | None:
    binary_path = shutil.which("uv", path=venv_path / "bin")
    if binary_path is not None:
        return Path(binary_path)

    return None


def is_dev_mode(venv_path: Path) -> bool:
    # If "dev.marker" exists in the venv directory, the user ran setup-dev.sh and is
    # considered a developer
    return (venv_path / "dev.marker").exists()


def update_deps(src_root: Path, venv_path: Path) -> None:
    uv_lock_hash_path = venv_path / "uv.lock.hash"

    current_hash = hash_file(src_root / "uv.lock")
    logging.debug(f"Current uv.lock hash: {current_hash}")

    stored_hash = None
    if uv_lock_hash_path.exists():
        stored_hash = uv_lock_hash_path.read_text().strip()
        logging.debug(f"Stored uv.lock hash: {stored_hash}")
    else:
        logging.debug("No stored hash found")

    # If the hashes don't match, update the dependencies
    if current_hash == stored_hash:
        return

    print("Detected outdated Pwndbg dependencies (uv.lock). Updating.")
    uv_path = find_uv(venv_path)
    if uv_path is None:
        print(
            "'uv' was not found on the $PATH. Please ensure it is installed and on the path, "
            "or run `./setup.sh` to manually update Python dependencies."
        )
        return

    dev_mode = is_dev_mode(venv_path)
    stdout, stderr, return_code = run_uv_install(uv_path, src_root, dev=dev_mode)
    if return_code == 0:
        uv_lock_hash_path.write_text(current_hash)

        # Only print the uv output if anything was actually updated
        if "No dependencies to install or update" not in stdout:
            # The output is usually long and ends up paginated. This
            # normally gets disabled later during initialization, but in
            # this case we disable it here to avoid pagination.
            gdb.execute("set pagination off", to_string=True)
            print(stdout)
    else:
        print(stderr, file=sys.stderr)


def fixup_paths(src_root: Path, venv_path: Path):
    site_pkgs_path = glob(str(venv_path / "lib/*/site-packages"))[0]

    # add virtualenv's site-packages to sys.path and run .pth files
    site.addsitedir(site_pkgs_path)

    # remove existing, system-level site-packages from sys.path
    for site_packages in site.getsitepackages():
        if site_packages in sys.path:
            sys.path.remove(site_packages)

    # Set virtualenv's bin path (needed for utility tools like ropper, pwntools etc)
    bin_path = str(venv_path / "bin")
    os.environ["PATH"] = bin_path + os.pathsep + os.environ.get("PATH", "")

    # Add pwndbg directory to sys.path so it can be imported
    sys.path.insert(0, str(src_root))

    # Push virtualenv's site-packages to the front
    sys.path.remove(site_pkgs_path)
    sys.path.insert(1, site_pkgs_path)


def get_venv_path(src_root: Path):
    venv_path_env = os.environ.get("PWNDBG_VENV_PATH")
    if venv_path_env:
        return Path(venv_path_env).expanduser().resolve()
    else:
        return src_root / ".venv"


def skip_venv(src_root) -> bool:
    return (
        os.environ.get("PWNDBG_VENV_PATH") == "PWNDBG_PLEASE_SKIP_VENV"
        or (src_root / ".skip-venv").exists()
    )


def init_logger():
    log_level_env = os.environ.get("PWNDBG_LOGLEVEL", "WARNING")
    log_level = getattr(logging, log_level_env.upper())

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Add a custom StreamHandler we will use to customize log message formatting. We
    # configure the handler later, after pwndbg has been imported.
    handler = logging.StreamHandler()
    root_logger.addHandler(handler)

    return handler


def check_doubleload():
    if "pwndbg" in sys.modules:
        print(
            "Detected double-loading of Pwndbg (likely from both .gdbinit and the Pwndbg portable build)."
        )
        print(
            "To fix this, please remove the line 'source your-path/gdbinit.py' from your .gdbinit file."
        )
        sys.exit(1)


def rewire_exit():
    major_ver = int(gdb.VERSION.split(".")[0])
    if major_ver <= 15:
        # On certain verions of gdb (used on ubuntu 24.04) using sys.exit() can cause
        # a segfault. See:
        # https://github.com/pwndbg/pwndbg/pull/2900#issuecomment-2825456636
        # https://sourceware.org/bugzilla/show_bug.cgi?id=31946
        def _patched_exit(exit_code):
            # argparse requires a SystemExit exception, otherwise our CLI commands will exit incorrectly on invalid arguments
            stack_list = traceback.extract_stack(limit=2)
            if len(stack_list) == 2:
                p = stack_list[0]
                if p.filename.endswith("/argparse.py"):
                    raise SystemExit()

            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(exit_code)

        sys.exit = _patched_exit


def main() -> None:
    profiler = cProfile.Profile()

    start_time = None
    if os.environ.get("PWNDBG_PROFILE") == "1":
        start_time = time.time()
        profiler.enable()

    rewire_exit()
    check_doubleload()

    handler = init_logger()

    src_root = Path(__file__).parent.resolve()
    if not skip_venv(src_root):
        venv_path = get_venv_path(src_root)
        if not venv_path.exists():
            print(f"Cannot find Pwndbg virtualenv directory: {venv_path}. Please re-run setup.sh")
            sys.exit(1)
        no_auto_update = os.getenv("PWNDBG_NO_AUTOUPDATE")
        if no_auto_update is None:
            update_deps(src_root, venv_path)
        fixup_paths(src_root, venv_path)

    # Force UTF-8 encoding (to_string=True to skip output appearing to the user)
    try:
        gdb.execute("set target-wide-charset UTF-8", to_string=True)
        gdb.execute("set charset UTF-8", to_string=True)
    except gdb.error as e:
        print(f"Warning: Cannot set gdb charset: '{e}'")

    # Add the original stdout methods back to gdb._GdbOutputFile for pwnlib colors
    sys.stdout.isatty = sys.__stdout__.isatty
    sys.stdout.fileno = sys.__stdout__.fileno

    import pwndbg  # noqa: F811
    import pwndbg.dbg.gdb

    pwndbg.dbg = pwndbg.dbg_mod.gdb.GDB()
    pwndbg.dbg.setup()

    import pwndbg.log
    import pwndbg.profiling

    # ColorFormatter relies on pwndbg being loaded, so we can't set it up until now
    handler.setFormatter(pwndbg.log.ColorFormatter())

    pwndbg.profiling.init(profiler, start_time)
    if os.environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
        pwndbg.profiling.profiler.start()


# We wrap everything in try/except so that we can exit GDB with an error code
# This is used by tests to check if gdbinit.py failed
try:
    main()

    # We've already imported this in `main`, but we reimport it here so that it's
    # available at the global scope when some starts a Python interpreter in GDB
    import pwndbg  # noqa: F401

except Exception:
    print(traceback.format_exc(), file=sys.stderr)
    sys.exit(1)
