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

import lldb


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
    command: List[str] = [str(binary_path), "sync", "--extra", "lldb"]
    if dev:
        command.extend(("--all-groups",))
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

    stored_hash = None
    if uv_lock_hash_path.exists():
        stored_hash = uv_lock_hash_path.read_text().strip()

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
    if site_pkgs_path in sys.path:
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


def main(debugger: lldb.SBDebugger, major: int, minor: int, debug: bool = False) -> None:
    if "pwndbg" in sys.modules:
        print("Detected double-loading of Pwndbg.")
        print("This should not happen. Please report this issue if you're not sure how to fix it.")
        sys.exit(1)

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

        no_auto_update = os.getenv("PWNDBG_NO_AUTOUPDATE")
        if no_auto_update is None:
            update_deps(src_root, venv_path)
        fixup_paths(src_root, venv_path)

    import pwndbg  # noqa: F811
    import pwndbg.dbg.lldb

    pwndbg.dbg_mod.lldb.LLDB_VERSION = (major, minor)

    pwndbg.dbg = pwndbg.dbg_mod.lldb.LLDB()
    pwndbg.dbg.setup(debugger, __name__, debug=debug)

    import pwndbg.profiling

    pwndbg.profiling.init(profiler, start_time)
    if os.environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
        pwndbg.profiling.profiler.start()
