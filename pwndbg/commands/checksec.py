#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.commands
import pwndbg.which
import pwndbg.wrappers.checksec

@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def checksec(file=None):
    '''
    Prints out the binary security settings. Attempts to call the binjitsu
    checksec first, and then falls back to checksec.sh.
    '''
    print(pwndbg.wrappers.checksec.get_raw_out())

