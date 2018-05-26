#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import pwndbg.arguments
import pwndbg.chain
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.disasm

parser = argparse.ArgumentParser(
    description='Prints determined arguments for call instruction. Pass --all to see all possible arguments.'
)
parser.add_argument('-f', '--force', action='store_true', help='Force displaying of all arguments.')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dumpargs(force=False):
    force_text = "Use `%s --force` to force the display." % dumpargs.__name__

    if not pwndbg.disasm.is_call() and not force:
        print("Cannot dump args as current instruction is not a call.\n" + force_text)
        return

    args = all_args() if force else call_args()

    if args:
        print('\n'.join(args))
    elif force:
        print("Couldn't resolve call arguments from registers.")
        print("Detected ABI: {} ({} bit) either doesn't pass arguments through registers or is not implemented. Maybe they are passed on the stack?".format(pwndbg.arch.current, pwndbg.arch.ptrsize*8))
    else:
        print("Couldn't resolve call arguments. Maybe the function doesn\'t take any?\n" + force_text)


def call_args():
    """
    Returns list of resolved call argument strings for display.
    Attempts to resolve the target and determine the number of arguments.
    Should be used only when being on a call instruction.
    """
    results = []

    for arg, value in pwndbg.arguments.get(pwndbg.disasm.one()):
        code   = False if arg.type == 'char' else True
        pretty = pwndbg.chain.format(value, code=code)
        results.append('        %-10s %s' % (arg.name+':', pretty))

    return results


def all_args():
    """
    Returns list of all argument strings for display.
    """
    results = []

    for name, value in pwndbg.arguments.arguments():
        results.append('%4s = %s' % (name, pwndbg.chain.format(value)))

    return results
