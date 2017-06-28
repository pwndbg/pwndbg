#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
import six

import pwndbg.commands
import pwndbg.memory


def xor_memory(address, key, count):
    """
    Helper function for xorring memory in gdb
    """
    mem = pwndbg.memory.read(address, count, partial=True)

    for index, byte in enumerate(mem):
        key_index = index % len(key)
        mem[index] = byte ^ ord(key[key_index])

    return mem

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def xor(address, key, count):
    '''xor(address, key, count)

    XOR ``count`` bytes at ``address`` with the key ``key``.
    '''
    if not isinstance(address, six.integer_types):
        try:
            address = int(address, 0)
        except ValueError:
            print('Invalid address %s' % address)
            return

    try:
        xorred_memory = xor_memory(address, key, count)
        pwndbg.memory.write(address, xorred_memory)
    except gdb.error as e:
        print(e)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def memfrob(address, count):
    '''memfrob(address, count)

    Run the memfrob command on a region of memory
    '''
    if not isinstance(address, six.integer_types):
        try:
            address = int(address, 0)
        except ValueError:
            print('Invalid address %s' % address)
            return

    try:
        xorred_memory = xor_memory(address, '*', count)
        pwndbg.memory.write(address, xorred_memory)
    except gdb.error as e:
        print(e)
