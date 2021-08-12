#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pwndbglib.auxv
import pwndbglib.chain
import pwndbglib.commands


@pwndbglib.commands.ArgparsedCommand('Print information from the Auxiliary ELF Vector.')
@pwndbglib.commands.OnlyWhenRunning
def auxv():
    for k, v in sorted(pwndbglib.auxv.get().items()):
        if v is not None:
            print(k.ljust(24), v if not isinstance(v, int) else pwndbglib.chain.format(v))
