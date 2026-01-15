from __future__ import annotations

import pwndbg.commands
import pwndbg.libc
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Show libc version and link to its sources", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
def libcinfo():
    libc = pwndbg.libc.get()
    version = libc.version()
    version_str = ".".join(map(str, version))

    print(f"libc version: {version_str}")
    # FIXME:
    # print(f"libc source link: https://ftp.gnu.org/gnu/libc/glibc-{glibc_version}.tar.gz")
    print(f"libc source link: {libc.source_url()}")

    print("Could not determine libc version.")
