from __future__ import annotations

import codecs
import os
import re
import subprocess

gdb_init_path = os.environ.get("GDB_INIT_PATH", "../gdbinit.py")
gdb_bin_path = os.environ.get("GDB_BIN_PATH", "gdb")


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

    command = [gdb_bin_path, "--silent", "--nx", "--nh"]

    for cmd in pybefore:
        command += ["--init-eval-command", cmd]

    if gdb_init_path:
        command += ["--command", gdb_init_path]

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
        r"loaded [0-9]+ pwndbg commands",
        r"loaded ### pwndbg commands",
        output,
    )

    # It also shows every single registered function, so we change it to xxx
    # so as to not break this test every time a new function is added
    output = re.sub(r"created (\$\w+, )*\$\w+ GDB functions", r"created xxx GDB functions", output)

    return output
