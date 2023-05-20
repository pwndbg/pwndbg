"""
Command to print the information of the current Thread Local Storage (TLS).
"""
import argparse

import pwndbg.commands
import pwndbg.gdblib.tls
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="Print out base address of the current Thread Local Storage (TLS).",
)

parser.add_argument(
    "-p",
    "--pthread-self",
    action="store_true",
    default=False,
    help="Try to get the address of TLS by calling pthread_self().",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def tls(pthread_self=False) -> None:
    tls_base = (
        pwndbg.gdblib.tls.find_address_with_register()
        if not pthread_self
        else pwndbg.gdblib.tls.find_address_with_pthread_self()
    )
    if pwndbg.gdblib.memory.is_readable_address(tls_base):
        print(message.success("Thread Local Storage (TLS) base: %#x" % tls_base))
        print(message.success("TLS is located at:"))
        print(message.notice(pwndbg.gdblib.vmmap.find(tls_base)))
        return
    print(message.error("Couldn't find Thread Local Storage (TLS) base."))
    if not pthread_self:
        print(
            message.notice(
                "You can try to use -p/--pthread option to get the address of TLS by calling pthread_self().\n"
                "(This might cause problems if the pthread_self() is not in libc or not initialized yet.)"
            )
        )
