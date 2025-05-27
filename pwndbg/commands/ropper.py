from __future__ import annotations

import argparse
import subprocess
import tempfile

import gdb

import pwndbg.aglib.proc
import pwndbg.aglib.vmmap
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="ROP gadget search with ropper.",
)
parser.add_argument("argument", nargs="*", type=str, help="Arguments to pass to ropper")


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.INTEGRATIONS,
    examples="""
pwndbg> ropper -- --console
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
(bash/ELF/x86_64)>
----
pwndbg> ropper -- --search 'pop rdi; ret;'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi; ret;

[INFO] File: /usr/bin/bash
0x000000000001ee23: pop rdi; ret;
    """,
)
@pwndbg.commands.OnlyWithFile
def ropper(argument) -> None:
    with tempfile.NamedTemporaryFile() as corefile:
        # If the process is running, dump a corefile so we get actual addresses.
        if pwndbg.aglib.proc.alive:
            filename = corefile.name
            gdb.execute(f"gcore {filename}")
        else:
            filename = pwndbg.aglib.proc.exe

        # Build up the command line to run
        cmd = ["ropper", "--file", filename]
        cmd += argument

        try:
            subprocess.call(cmd)
        except Exception:
            print("Could not run ropper.  Please ensure it's installed and in $PATH.")
