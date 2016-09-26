#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.commands
import pwndbg.regs


class segment(gdb.Function):
    """Get the flat address of memory based off of the named segment register.
    """
    def __init__(self, name):
        super(segment, self).__init__(name)
        self.name = name
    def invoke(self, arg=0):
        result = getattr(pwndbg.regs, self.name)
        return result + arg

segment('fsbase')
segment('gsbase')

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def fsbase():
    """
    Prints out the FS base address.  See also $fsbase.
    """
    print(hex(int(pwndbg.regs.fsbase)))


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def gsbase():
    """
    Prints out the GS base address.  See also $gsbase.
    """
    print(hex(int(pwndbg.regs.gsbase)))
