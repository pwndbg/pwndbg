#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import site
import subprocess
import sys
import sysconfig


def get_gdb_version(path: str) -> tuple[str, ...]:
    result = subprocess.run(
        [
            path,
            "-nx",
            "--batch",
            "-iex",
            "py import sysconfig; print(sysconfig.get_config_var('INSTSONAME'), sysconfig.get_config_var('VERSION'))",
        ],
        capture_output=True,
        text=True,
    )

    arr = result.stdout.strip().split(" ", 1)
    if len(arr) != 2:
        return "", ""
    return arr[0], arr[1]


def get_venv_bin_path() -> str:
    bin_dir = "Scripts" if os.name == "nt" else "bin"
    return os.path.join(sys.prefix, bin_dir)


def prepend_venv_bin_to_path():
    # Set virtualenv's bin path (needed for utility tools like ropper, pwntools etc)
    venv_bin = get_venv_bin_path()
    path_elements = os.environ.get("PATH", "").split(os.pathsep)
    if venv_bin in path_elements:
        return

    path_elements.insert(0, venv_bin)
    os.environ["PATH"] = os.pathsep.join(path_elements)


def main():
    prepend_venv_bin_to_path()

    gdb_argv = [
        sys.argv[0],
        "-q",
        "-nx",
        "-iex",
        "py import pwndbginit.gdbinit; pwndbginit.gdbinit.main_try()",
        *sys.argv[1:],
    ]
    sys.argv = gdb_argv

    try:
        from gdb_for_pwndbg.gdb import main  # type: ignore[import-untyped]

        main()
        return
    except ImportError:
        pass

    gdb_path = shutil.which("gdb")
    if not gdb_path:
        print("ERROR: Could not find 'gdb' binary")
        sys.exit(1)

    envs = os.environ.copy()
    envs["PYTHONNOUSERSITE"] = "1"
    envs["PYTHONPATH"] = ":".join(site.getsitepackages())

    # Ensure arg0 points to the gdb binary; otherwise GDB can pick up a wrong PYTHONHOME.
    sys.argv[0] = gdb_path

    # sys.prefix/sys.exec_prefix must point to the virtual environment,
    # otherwise our auto-upgrade mechanism won't work when the package is installed in editable mode
    prefix_cmd = (
        f"py import sys; sys.prefix = {sys.prefix!r}; sys.exec_prefix = {sys.exec_prefix!r}"
    )
    sys.argv.insert(1, prefix_cmd)
    sys.argv.insert(1, "-iex")

    expected = (sysconfig.get_config_var("INSTSONAME"), sysconfig.get_config_var("VERSION"))
    have = get_gdb_version(gdb_path)
    if have != expected:
        print(
            f"ERROR: GDB is compiled for Python {have}, but your Python interpreter is {expected} .\n\n"
            "If you installed Pwndbg with `uv tool install` and want to use system GDB you may try:\n"
            """  PY_VER=$(gdb -nx --batch -iex 'py import sysconfig; print(sysconfig.get_config_var("VERSION"))')\n"""
            "  uv tool install --python=$PY_VER .\n\n"
            "(add --editable if you are doing development)\n"
            "(the python version may be wrong because our development scripts switch between them)"
        )
        sys.exit(1)

    os.execve(gdb_path, sys.argv, env=envs)


if __name__ == "__main__":
    main()
