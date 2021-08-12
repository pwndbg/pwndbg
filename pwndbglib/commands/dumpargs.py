#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import pwndbglib.arguments
import pwndbglib.chain
import pwndbglib.commands
import pwndbglib.commands.telescope
import pwndbglib.disasm

parser = argparse.ArgumentParser(
    description='Prints determined arguments for call instruction.'
)
parser.add_argument('-f', '--force', action='store_true', help='Force displaying of all arguments.')


@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def dumpargs(force=False):
    args = (not force and call_args()) or all_args()

    if args:
        print('\n'.join(args))
    else:
        print("Couldn't resolve call arguments from registers.")
        print("Detected ABI: {} ({} bit) either doesn't pass arguments through registers or is not implemented. Maybe they are passed on the stack?".format(pwndbglib.arch.current, pwndbglib.arch.ptrsize * 8))


def call_args():
    """
    Returns list of resolved call argument strings for display.
    Attempts to resolve the target and determine the number of arguments.
    Should be used only when being on a call instruction.
    """
    results = []

    for arg, value in pwndbglib.arguments.get(pwndbglib.disasm.one()):
        code   = False if arg.type == 'char' else True
        pretty = pwndbglib.chain.format(value, code=code)
        results.append('        %-10s %s' % (arg.name+':', pretty))

    return results


def all_args():
    """
    Returns list of all argument strings for display.
    """
    results = []

    for name, value in pwndbglib.arguments.arguments():
        results.append('%4s = %s' % (name, pwndbglib.chain.format(value)))

    return results
