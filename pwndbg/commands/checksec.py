from __future__ import annotations

import pwndbg.color
import pwndbg.commands
import pwndbg.gdblib.file
import pwndbg.wrappers.checksec


def color_line(line: str) -> str:
    return pwndbg.color.normal(
        line.replace("*", pwndbg.color.green("*"))
        .replace(":", f":{pwndbg.color.GREEN}")
        .replace("No", f"{pwndbg.color.RED}No")
    )


def color_lines(output: str) -> str:
    return "\n".join(map(color_line, output.split("\n")))


@pwndbg.commands.ArgparsedCommand("Prints out the binary security settings using `checksec`.")
@pwndbg.commands.OnlyWithFile
def checksec() -> None:
    output = pwndbg.wrappers.checksec.get_raw_out(pwndbg.gdblib.file.get_proc_exe_file())
    print(color_lines(output))
