from __future__ import annotations

import argparse
from typing import List

import pwndbg
import pwndbg.aglib.memory
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Extracts and displays ASCII strings from readable memory pages of the debugged process."
)

parser.add_argument("-n", type=int, default=4, help="Minimum length of ASCII strings to include")
parser.add_argument(
    "page_names",
    type=str,
    nargs="*",
    default=[],
    help="Mapping to search [e.g. libc].\nCan be used with multiple mappings [e.g libc heap stack]",
)
parser.add_argument(
    "--save-as",
    type=str,
    default=None,
    help="Sets the filename for the output of this command [e.g. --save-as='out.txt']",
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def strings(n: int = 4, page_names: List[str] = [], save_as: str = None):
    # Get only readable pages and those that match the page_names filter
    pages = (
        p
        for p in pwndbg.aglib.vmmap.get()
        if p.read and ((not page_names) or any(name in p.objfile for name in page_names))
    )

    f = open(save_as, "w") if save_as else None

    for page in pages:
        for string in pwndbg.aglib.strings.yield_in_page(page, n):
            print(string, file=f)

    if f:
        f.close()
