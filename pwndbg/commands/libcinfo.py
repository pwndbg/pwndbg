from __future__ import annotations

import pwndbg.commands
import pwndbg.libc
import pwndbg.libc.facade
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Show libc version and link to its sources", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
def libcinfo():
    # FIXME: What if some info isn't available?

    version = pwndbg.libc.facade.version()
    version_str = ".".join(map(str, version))

    print(f"libc version: {version_str}")
    urls = pwndbg.libc.urls()
    print("URLs:")
    print("    project homepage:      ", urls.homepage)
    print("    read the source:       ", urls.versioned_readable_source)
    print("    download the archive:  ", urls.versioned_compressed_source)
    print("    git clone              ", urls.git)
