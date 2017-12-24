#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.commands
import pwndbg.which
import pwndbg.wrappers.checksec


@pwndbg.commands.ArgparsedCommand('Prints out the binary security settings using `checksec`.')
@pwndbg.commands.OnlyWithFile
def checksec():
    print(pwndbg.wrappers.checksec.get_raw_out())
