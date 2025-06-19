#!/usr/bin/env python3
from typing import Tuple

import os
import sys
import shutil
import sysconfig
import subprocess

def get_gdb_version(path: str) -> Tuple[str, str]:
    result = subprocess.run(
        [
            path, "-nx", "--batch",
            "-iex", "py import sysconfig; print(sysconfig.get_config_var('INSTSONAME'), sysconfig.get_config_var('VERSION'))"
        ],
        capture_output=True,
        text=True
    )
    return tuple(result.stdout.strip().split(' ', 2))

def main():
    gdb_argv = [sys.argv[0], "-q", "-nx", "-iex", "py import pwndbginit.gdbinit", *sys.argv[1:]]
    sys.argv = gdb_argv

    try:
        from gdb_for_pwndbg.gdb import main
        main()
        return
    except ImportError:
        pass

    gdb_path = shutil.which("gdb")
    if not gdb_path:
        print(f"ERROR: Could not find gdb for pwndbg in {gdb_path}")
        sys.exit(1)

    envs = os.environ.copy()
    envs['PYTHONNOUSERSITE'] = '1'
    envs['PYTHONPATH'] = ':'.join(sys.path)
    envs['PYTHONHOME'] = ':'.join([sys.prefix, sys.exec_prefix])

    expected = (sysconfig.get_config_var("INSTSONAME"), sysconfig.get_config_var("VERSION"))
    have = get_gdb_version(gdb_path)
    if have != expected:
        print(f"ERROR: GDB is compiled for Python {have}, but your Python interpreter is {expected}")
        sys.exit(1)

    os.execve(gdb_path, sys.argv, env=envs)

if __name__ == "__main__":
    main()
