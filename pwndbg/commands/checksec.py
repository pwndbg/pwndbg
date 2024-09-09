from __future__ import annotations

import argparse

import pwndbg.aglib.file
import pwndbg.color
import pwndbg.commands
import pwndbg.wrappers.checksec

parser = argparse.ArgumentParser(
    description="Prints out the binary security settings using `checksec`."
)

parser.add_argument("-f", "--file", type=str, help="Specify the file to run `checksec` on.")


@pwndbg.commands.ArgparsedCommand(parser, command_name="checksec")
@pwndbg.commands.OnlyWithFile
def checksec(file: str) -> None:
    local_path = file or pwndbg.aglib.file.get_proc_exe_file()
    print(pwndbg.wrappers.checksec.get_raw_out(local_path))
