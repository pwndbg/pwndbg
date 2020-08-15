#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbg.commands
import pwndbg.which
import pwndbg.wrappers.checksec


@pwndbg.commands.ArgparsedCommand('Prints out the binary security settings using `checksec`.')
@pwndbg.commands.OnlyWithFile
def checksec():
    print(pwndbg.wrappers.checksec.get_raw_out())
