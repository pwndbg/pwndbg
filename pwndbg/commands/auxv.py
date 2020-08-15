#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pwndbg.auxv
import pwndbg.chain
import pwndbg.commands


@pwndbg.commands.ArgparsedCommand('Print information from the Auxiliary ELF Vector.')
@pwndbg.commands.OnlyWhenRunning
def auxv():
    for k, v in sorted(pwndbg.auxv.get().items()):
        if v is not None:
            print(k.ljust(24), v if not isinstance(v, int) else pwndbg.chain.format(v))
