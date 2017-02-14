#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.color
import pwndbg.commands
import pwndbg.dt
import pwndbg.vmmap


@pwndbg.commands.Command
def dt(typename, address=None):
    """
    Dump out information on a type (e.g. ucontext_t).

    Optionally overlay that information at an address.
    """
    if address is not None:
        address = pwndbg.commands.fix(address)
    print(pwndbg.dt.dt(typename, addr=address))
