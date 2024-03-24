from __future__ import annotations

import argparse


import pwndbg.color
import pwndbg.commands
import pwndbg.gdblib.file
import pwndbg.wrappers.checksec

parser = argparse.ArgumentParser(
    description="Prints out the binary security settings using `checksec`."
)

parser.add_argument("-f", "--file", type=str, help="Specify the file to run `checksec` on.")


def color_line(line: str) -> str:
    return pwndbg.color.normal(
        line.replace("*", pwndbg.color.green("*"))
        .replace(":", f":{pwndbg.color.GREEN}")
        .replace("No", f"{pwndbg.color.RED}No")
    )


def color_lines(output: str) -> str:
    return "\n".join(map(color_line, output.split("\n")))


@pwndbg.commands.ArgparsedCommand(parser, command_name="checksec")
@pwndbg.commands.OnlyWithFile
def checksec(file: str) -> None:
    local_path = file or pwndbg.gdblib.file.get_proc_exe_file()
    output = pwndbg.wrappers.checksec.get_raw_out(local_path)
    print(color_lines(output))
