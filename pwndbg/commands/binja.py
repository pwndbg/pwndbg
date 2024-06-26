import pwndbg.binja
import pwndbg.gdblib.events
import pwndbg.commands
from pwndbg.commands import CommandCategory
import gdb


@pwndbg.commands.ArgparsedCommand(
    "Synchronize Binary Ninja's cursor with GDB.",
    category=CommandCategory.INTEGRATIONS,
    command_name="bn-sync",
    aliases=["bns"]
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.binja.with_bn
def bn_sync(*args) -> None:
    """
    Synchronize IDA's cursor with GDB
    """
    try:
        pc = int(gdb.selected_frame().pc())
        pwndbg.binja.navigate_to(pc)
    except Exception:
        pass
