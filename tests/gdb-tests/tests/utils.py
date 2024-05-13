from __future__ import annotations

import codecs
import os
import re
import subprocess

GDB_INIT_PATH = os.environ.get("GDB_INIT_PATH", "../../gdbinit.py")


def run_gdb_with_script(
    binary="",
    core="",
    stdin_input=None,
    pybefore=None,
    pyafter=None,
    timeout=None,
):
    """
    Runs GDB with given commands launched before and after loading of gdbinit.py
    Returns GDB output.
    """
    pybefore = ([pybefore] if isinstance(pybefore, str) else pybefore) or []
    pyafter = ([pyafter] if isinstance(pyafter, str) else pyafter) or []

    command = ["gdb", "--silent", "--nx", "--nh"]

    for cmd in pybefore:
        command += ["--eval-command", cmd]

    command += ["--command", GDB_INIT_PATH]

    if binary:
        command += [binary]

    if core:
        command += ["--core", core]

    for cmd in pyafter:
        command += ["--eval-command", cmd]

    command += ["--eval-command", "quit"]

    print(f"Launching command: {command}")
    output = subprocess.check_output(
        command, stderr=subprocess.STDOUT, timeout=timeout, input=stdin_input
    )

    # Python 3 returns bytes-like object so lets have it consistent
    output = codecs.decode(output, "utf8")

    # The pwndbg banner shows number of loaded commands, it might differ between
    # testing environments, so lets change it to ###
    output = re.sub(
        r"loaded [0-9]+ pwndbg commands and [0-9]+ shell commands",
        r"loaded ### pwndbg commands and ### shell commands",
        output,
    )

    return output
