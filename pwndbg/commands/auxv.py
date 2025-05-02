from __future__ import annotations

import pwndbg.auxv
import pwndbg.chain
import pwndbg.commands
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Print information from the Auxiliary ELF Vector.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def auxv() -> None:
    for k, v in pwndbg.auxv.get().items():
        if v is not None:
            print(k.ljust(24), v if not isinstance(v, int) else pwndbg.chain.format(v))


@pwndbg.commands.Command(
    "Explore and print information from the Auxiliary ELF Vector.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def auxv_explore() -> None:
    old_value = pwndbg.config.auto_explore_auxv.value
    pwndbg.config.auto_explore_auxv.value = "yes"
    try:
        pwndbg.auxv.get.cache.clear()  # type: ignore[attr-defined]
        pwndbg.auxv.get()
    finally:
        pwndbg.config.auto_explore_auxv.value = old_value

    auxv()
