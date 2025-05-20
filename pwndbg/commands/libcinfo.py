from __future__ import annotations

import pwndbg.commands
import pwndbg.glibc
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Show libc version and link to its sources", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
def libcinfo():
    glibc_version = pwndbg.glibc.get_version()

    if glibc_version:
        glibc_version = ".".join(map(str, glibc_version))
        print(f"libc version: {glibc_version}")
        print(f"libc source link: https://ftp.gnu.org/gnu/libc/glibc-{glibc_version}.tar.gz")
        return

    print("Could not determine libc version.")
