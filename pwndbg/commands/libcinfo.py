from __future__ import annotations

import pwndbg.color.memory
import pwndbg.commands
import pwndbg.libc
import pwndbg.libc.facade
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Show various information about the currently used libc", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def libcinfo() -> None:
    version = pwndbg.libc.facade.version()
    version_str = ".".join(map(str, version))
    urls_heading = "URLs:"
    if version_str == "-1.-1":
        version_str = "no version information"
        urls_heading = "URLs (unversioned):"

    print(f"libc: {pwndbg.libc.which().value}")
    print(f"libc version: {version_str}")
    print(
        "linked:",
        "dynamically" if pwndbg.dbg.selected_inferior().is_dynamically_linked() else "statically",
    )

    urls = pwndbg.libc.urls()
    print(urls_heading)
    print("    project homepage:      ", urls.homepage)
    print("    read the source:       ", urls.versioned_readable_source)
    print("    download the archive:  ", urls.versioned_compressed_source)
    print("    git clone              ", urls.git)
    print("Mappings:")
    print("    libc is at:            ", pwndbg.color.memory.get(pwndbg.libc.addr()))
    print("          ", pwndbg.libc.filepath())
    print("    ld is at:              ", pwndbg.color.memory.get(pwndbg.libc.loader_addr()))
    print("          ", pwndbg.libc.loader_filepath())
    print("Symbolication:")
    print("    has exported symbols: ", "yes" if pwndbg.libc.has_exported_symbols() else "no")
    print("    has internal symbols: ", "yes" if pwndbg.libc.has_internal_symbols() else "no")
    print("    has debug info:       ", "yes" if pwndbg.libc.has_debug_info() else "no")
