#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbglib.commands
import pwndbglib.which
import pwndbglib.wrappers.checksec


@pwndbglib.commands.ArgparsedCommand('Prints out the binary security settings using `checksec`.')
@pwndbglib.commands.OnlyWithFile
def checksec():
    print(pwndbglib.wrappers.checksec.get_raw_out())
