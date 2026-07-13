from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path


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
    binary_path: os.PathLike[str], src_root: Path, venv_path: Path, dev: bool = False
) -> tuple[str, str, int]:
    # Check if the package was installed using: `uv tool install --editable .[lldb,gdb]`
    # Tools are located at: ${HOME}/.local/share/uv/tools/${TOOL_NAME}/uv-receipt.toml
    is_tool_install = (venv_path / "uv-receipt.toml").exists()
    if is_tool_install:
        tool_name = venv_path.name
        command: list[str] = [str(binary_path), "tool", "upgrade", tool_name]
    else:
        # --inexact makes it so any installed extras aren't uninstalled
        # (it will also leave in dropped deps, but what can you do /shrug)
        command = [str(binary_path), "sync", "--inexact"]
        if dev:
            command.append("--all-groups")
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


def update_deps(src_root: Path) -> None:
    venv_path = Path(sys.prefix)
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
    stdout, stderr, return_code = run_uv_install(uv_path, src_root, venv_path, dev=dev_mode)
    if return_code == 0:
        uv_lock_hash_path.write_text(current_hash)

        # Only print the uv output if anything was actually updated
        if "No dependencies to install or update" not in stdout:
            print(stdout)
    else:
        print(stderr, file=sys.stderr)
        print("\x1b[31mERROR: Pwndbg failed to update with the above uv error.\x1b[0m")
        print(
            "\x1b[31m"
            "ERROR: Re-run with PWNDBG_NO_AUTOUPDATE=1 if you intend to run without an update."
            "\x1b[0m"
        )
        sys.exit(return_code)


def is_system_installation(src_root: Path) -> bool:
    # NOTE: This is intentionally duplicated (inlined) in the top-level `gdbinit.py`
    # so that gdbinit doesn't import the `pwndbginit` package before `fixup_paths()`
    # corrects `sys.path` (see https://github.com/pwndbg/pwndbg/issues/3963). If you
    # change the logic here, update `is_system_installation` in `gdbinit.py` too.
    #
    # If pwndbg is installed in `/venv/lib/pythonX.Y/site-packages/pwndbg/`,
    # the `.pwndbg_root` file will not exist because `src_root` will point to the
    # `/venv/lib/pythonX.Y/site-packages/` directory, not the original source directory
    #
    # However, if pwndbg is installed in editable mode (our recommended way), this file will exist,
    # and the condition will be False, allowing auto-update.
    is_system_install = not (src_root / ".pwndbg_root").exists()
    if is_system_install:
        return True

    return False


def skip_autoupdate(src_root: Path) -> bool:
    no_auto_update = os.getenv("PWNDBG_NO_AUTOUPDATE") is not None
    if no_auto_update:
        return True

    if is_system_installation(src_root):
        return True

    return False


def verify_venv():
    src_root = Path(__file__).parent.parent.resolve()
    if skip_autoupdate(src_root):
        return

    update_deps(src_root)
