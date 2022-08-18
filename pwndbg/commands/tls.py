"""
Command to print the information of the current Thread Local Storage (TLS).
"""
import argparse

import pwndbg.commands
import pwndbg.tls
from pwndbg.color import message


@pwndbg.commands.ArgparsedCommand('Print out base address of the current Thread Local Storage (TLS).')
@pwndbg.commands.OnlyWhenRunning
def tls():
    tls_base = pwndbg.tls.address
    if tls_base:
        print(message.success('Thread Local Storage (TLS) base: %#x' % tls_base))
    else:
        print(message.error("Couldn't find Thread Local Storage (TLS) base."))
