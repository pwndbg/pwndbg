"""
Command to print the information of the current Thread Local Storage (TLS).
"""

import pwndbg.commands
import pwndbg.gdblib.tls
from pwndbg.color import message
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Print out base address of the current Thread Local Storage (TLS).",
    category=CommandCategory.LINUX,
)
@pwndbg.commands.OnlyWhenRunning
def tls() -> None:
    tls_base = pwndbg.gdblib.tls.address
    if tls_base:
        print(message.success("Thread Local Storage (TLS) base: %#x" % tls_base))
    else:
        print(message.error("Couldn't find Thread Local Storage (TLS) base."))
