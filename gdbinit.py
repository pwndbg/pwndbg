from __future__ import annotations

import cProfile
import hashlib
import os
import shutil
import site
import subprocess
import sys
import time
from glob import glob
from pathlib import Path
from typing import List
from typing import Tuple

import gdb


def hash_file(file_path: str | Path) -> str:
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256()
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            file_hash.update(chunk)
    return file_hash.hexdigest()


def run_poetry_install(poetry_path: os.PathLike[str], dev: bool = False) -> Tuple[str, str, int]:
    command: List[str | os.PathLike[str]] = [poetry_path, "install"]
    if dev:
        command.extend(("--with", "dev"))
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def find_poetry() -> Path | None:
    poetry_path = shutil.which("poetry")
    if poetry_path is not None:
        return Path(poetry_path)

    # On some systems `poetry` is installed in "~/.local/bin/" but this directory is
    # not on the $PATH
    poetry_path = Path("~/.local/bin/poetry").expanduser()
    if poetry_path.exists():
        return poetry_path

    return None


def is_dev_mode(venv_path: Path) -> bool:
    # If "dev.marker" exists in the venv directory, the user ran setup-dev.sh and is
    # considered a developer
    return (venv_path / "dev.marker").exists()


def update_deps(src_root: Path, venv_path: Path) -> None:
    poetry_lock_hash_path = venv_path / "poetry.lock.hash"

    current_hash = hash_file(src_root / "poetry.lock")
    stored_hash = None
    if poetry_lock_hash_path.exists():
        stored_hash = poetry_lock_hash_path.read_text().strip()

    # If the hashes don't match, update the dependencies
    if current_hash != stored_hash:
        poetry_path = find_poetry()
        if poetry_path is None:
            print(
                "Poetry was not found on the $PATH. Please ensure it is installed and on the path, "
                "or run `./setup.sh` to manually update Python dependencies."
            )
            return

        dev_mode = is_dev_mode(venv_path)
        stdout, stderr, return_code = run_poetry_install(poetry_path, dev=dev_mode)
        if return_code == 0:
            poetry_lock_hash_path.write_text(current_hash)

            # Only print the poetry output if anything was actually updated
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


def main() -> None:
    profiler = cProfile.Profile()

    start_time = None
    if os.environ.get("PWNDBG_PROFILE") == "1":
        start_time = time.time()
        profiler.enable()

    src_root = Path(__file__).parent.resolve()
    if not skip_venv(src_root):
        venv_path = get_venv_path(src_root)
        if not venv_path.exists():
            print(f"Cannot find Pwndbg virtualenv directory: {venv_path}. Please re-run setup.sh")
            sys.exit(1)

        update_deps(src_root, venv_path)
        fixup_paths(src_root, venv_path)

    # Force UTF-8 encoding (to_string=True to skip output appearing to the user)
    gdb.execute("set charset UTF-8", to_string=True)
    os.environ["PWNLIB_NOTERM"] = "1"

    import pwndbg  # noqa: F401
    import pwndbg.profiling

    pwndbg.profiling.init(profiler, start_time)
    if os.environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
        pwndbg.profiling.profiler.start()


main()
