from __future__ import annotations

import cProfile
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import time
from logging import StreamHandler
from pathlib import Path
from typing import TextIO


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


def verify_venv() -> None:
    src_root = Path(__file__).parent.parent.resolve()
    if skip_autoupdate(src_root):
        return

    update_deps(src_root)


def setup_load_profiler() -> tuple[cProfile.Profile, float | None]:
    profiler = cProfile.Profile()

    load_profile_start_time: float | None = None
    if os.environ.get("PWNDBG_PROFILE") == "1":
        load_profile_start_time = time.time()
        profiler.enable()

    return (profiler, load_profile_start_time)


def set_debuginfod_timeouts() -> None:
    """
    The default value for DEBUGINFOD_TIMEOUT is 90 seconds. Since
    https://debuginfod.ubuntu.com/ is often broken, the download can
    stall for a while.

    This is a double-problem because GDB / gnu libdebuginfod does not
    serve a Ctrl-C during this time. See #4079 for extra info.

    Set more sane values if the user did not already touch them.
    """
    if "DEBUGINFOD_TIMEOUT" not in os.environ:
        # default is 90
        os.environ["DEBUGINFOD_TIMEOUT"] = "5"
    if "DEBUGINFOD_RETRY_LIMIT" not in os.environ:
        # default is 2
        os.environ["DEBUGINFOD_RETRY_LIMIT"] = "0"


def init_logger() -> logging.StreamHandler[TextIO]:
    log_level_env = os.environ.get("PWNDBG_LOGLEVEL", "WARNING")
    log_level = getattr(logging, log_level_env.upper())

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Add a custom StreamHandler we will use to customize log message formatting. We
    # configure the handler later, after pwndbg has been imported.
    handler = logging.StreamHandler()
    root_logger.addHandler(handler)

    return handler


def pre_debugger_init() -> None:
    """
    Initialization to run before any debugger-specific stuff gets loaded.
    """
    import pwndbg

    # Marker used to detect double-loading (checked in ../gdbinit.py).
    # Can happen if you run `pwndbg /bin/sh` and have `source /path/to/gdbinit.py`
    # in your `~/.gdbinit`.
    # Note that the variable name is a bit deceptive since this also gets set
    # from `gdb` + `source /path/to/gdbinit.py` and not only the `pwndbg` command,
    # but renaming it now will cause desync for users who have different versions
    # of pwndbg installed.
    pwndbg._is_loaded_from_pwndbg = True

    set_debuginfod_timeouts()


def post_debugger_init(
    profiler, load_profile_start_time: float | None, log_handler: StreamHandler[TextIO]
) -> None:
    """
    Initialization to run after Debugger.setup() gets run.
    """
    import pwndbg
    import pwndbg.log
    import pwndbg.profiling

    pwndbg.profiling.init(profiler, load_profile_start_time)
    assert pwndbg.profiling.profiler is not None

    if os.environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
        pwndbg.profiling.profiler.start()

    # ColorFormatter relies on pwndbg being loaded, so we can't set it up until now
    log_handler.setFormatter(pwndbg.log.ColorFormatter())
