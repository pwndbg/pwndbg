import argparse
import subprocess
import tempfile

import gdb

import pwndbg.commands
import pwndbg.gdblib.vmmap

parser = argparse.ArgumentParser(
    description="ROP gadget search with ropper.",
    epilog="Example: ropper -- --console; ropper -- --search 'mov e?x'",
)
parser.add_argument("argument", nargs="*", type=str, help="Arguments to pass to ropper")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def ropper(argument):
    with tempfile.NamedTemporaryFile() as corefile:

        # If the process is running, dump a corefile so we get actual addresses.
        if pwndbg.gdblib.proc.alive:
            filename = corefile.name
            gdb.execute("gcore %s" % filename)
        else:
            filename = pwndbg.gdblib.proc.exe

        # Build up the command line to run
        cmd = ["ropper", "--file", filename]
        cmd += argument

        try:
            io = subprocess.call(cmd)
        except Exception:
            print("Could not run ropper.  Please ensure it's installed and in $PATH.")
