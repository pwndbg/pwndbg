from __future__ import annotations

import argparse
import re
from typing import List

import pwndbg
import pwndbg.aglib.memory
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.lib.memory import Page

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


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def strings(n: int = 4, page_names: List[str] = [], save_as: str = None):
    # Extract pages with PROT_READ permission
    readable_pages: List[Page] = [page for page in pwndbg.aglib.vmmap.get() if page.read]

    for page in readable_pages:
        if page_names and not any(name in page.objfile for name in page_names):
            continue  # skip if page does not belong to any of the specified mappings

        count = page.memsz
        start_address = page.vaddr

        try:
            data = pwndbg.aglib.memory.read(addr=start_address, count=count)
        except pwndbg.dbg_mod.Error as e:
            print(f"Skipping inaccessible page at {start_address:#x}: {e}")
            continue  # skip if access is denied

        # all strings in the `data`
        strings: List[bytes] = re.findall(rb"[ -~]{%d,}" % n, data)
        decoded_strings: List[str] = [s.decode("ascii", errors="ignore") for s in strings]

        if not save_as:
            for string in decoded_strings:
                print(string)
            continue

        with open(save_as, "w") as f:
            f.writelines(string + "\n" for string in decoded_strings)
