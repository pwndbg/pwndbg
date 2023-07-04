import pwndbg.auxv
import pwndbg.chain
import pwndbg.commands
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Print information from the Auxiliary ELF Vector.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def auxv() -> None:
    for k, v in pwndbg.auxv.get().items():
        if v is not None:
            print(k.ljust(24), v if not isinstance(v, int) else pwndbg.chain.format(v))
