from __future__ import annotations

from typing import cast

import pwndbg.commands
import pwndbg.gdblib.file
import pwndbg.wrappers.checksec

NEW_LINE = "\n"


class colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    RESET = "\033[0m"


def color_line(line: str) -> str:
    return (
        line.replace("*", colors.BLUE + "*" + colors.RESET)
        .replace(":", ":" + colors.GREEN)
        .replace("No", colors.RED + "No")
    ) + colors.RESET


def color_lines(lines: list[str]) -> str:
    return NEW_LINE.join(list(map(color_line, lines)))


@pwndbg.commands.ArgparsedCommand("Prints out the binary security settings using `checksec`.")
@pwndbg.commands.OnlyWithFile
def checksec() -> None:
    print(
        color_lines(
            cast(
                str, pwndbg.wrappers.checksec.get_raw_out(pwndbg.gdblib.file.get_proc_exe_file())
            ).split(NEW_LINE)
        )
    )
