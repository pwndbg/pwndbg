from __future__ import print_function
from __future__ import unicode_literals

import six

import gdb
import pwndbg.auxv
import pwndbg.chain
import pwndbg.commands


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def auxv():
    """
    Print information from the Auxiliary ELF Vector.
    """
    for k,v in sorted(pwndbg.auxv.get().items()):
        if v is not None:
            print(k.ljust(24), v if not isinstance(v, six.integer_types) else pwndbg.chain.format(v))
