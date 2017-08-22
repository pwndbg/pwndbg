#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import pwndbg.arguments
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.disasm


parser = argparse.ArgumentParser(
    description='Prints determined arguments for call instruction. Pass --all to see all possible arguments.'
)
parser.add_argument('--all', action='store_true', help='Force displaying of all arguments.')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dumpargs(all=False):
    if all:
        all_args()
    else:
        print('\n'.join(call_args()))


def call_args():
    """
    Yields resolved call argument strings for display.
    Attempts to resolve the target and determine the number of arguments.
    Should be used only when being on a call instruction.
    """
    for arg, value in pwndbg.arguments.get(pwndbg.disasm.one()):
        code   = False if arg.type == 'char' else True
        pretty = pwndbg.chain.format(value, code=code)
        yield '        %-10s %s' % (arg.name+':', pretty)


def all_args():
    """
    Yields all argument strings for display.
    """
    for name, value in pwndbg.arguments.arguments():
        print('%4s = ' % name, end='')
        pwndbg.commands.telescope.telescope(address=value, count=1, print_offsets=False)
