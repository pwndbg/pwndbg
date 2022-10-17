import argparse
import re
import subprocess
import tempfile

import gdb

import pwndbg.commands
import pwndbg.gdblib.vmmap

parser = argparse.ArgumentParser(
    description="Dump ROP gadgets with Jon Salwan's ROPgadget tool.",
    epilog="Example: rop --grep 'pop rdi' -- --nojop",
)
parser.add_argument("--grep", type=str, help="String to grep the output for")
parser.add_argument("argument", nargs="*", type=str, help="Arguments to pass to ROPgadget")


@pwndbg.commands.ArgparsedCommand(parser, aliases=["ropgadget"])
@pwndbg.commands.OnlyWithFile
def rop(grep, argument):
    with tempfile.NamedTemporaryFile() as corefile:

        # If the process is running, dump a corefile so we get actual addresses.
        if pwndbg.gdblib.proc.alive:
            filename = corefile.name
            gdb.execute("gcore %s" % filename)
        else:
            filename = pwndbg.gdblib.proc.exe

        # Build up the command line to run
        cmd = ["ROPgadget", "--binary", filename]
        cmd += argument

        try:
            io = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        except Exception:
            print("Could not run ROPgadget.  Please ensure it's installed and in $PATH.")
            return

        (stdout, stderr) = io.communicate()

        stdout = stdout.decode("latin-1")

        if not grep:
            print(stdout)
            return

        for line in stdout.splitlines():
            if re.search(grep, line):
                print(line)
