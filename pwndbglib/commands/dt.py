#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import gdb

import pwndbglib.color
import pwndbglib.commands
import pwndbglib.dt
import pwndbglib.vmmap

parser = argparse.ArgumentParser()
parser.description = """
    Dump out information on a type (e.g. ucontext_t).

    Optionally overlay that information at an address.
    """
parser.add_argument("typename", type=str, help="The name of the structure being dumped.")
parser.add_argument("address", type=int, nargs="?", default=None, help="The address of the structure.")
@pwndbglib.commands.ArgparsedCommand(parser)
def dt(typename, address=None):
    """
    Dump out information on a type (e.g. ucontext_t).

    Optionally overlay that information at an address.
    """
    if address is not None:
        address = pwndbglib.commands.fix(address)
    print(pwndbglib.dt.dt(typename, addr=address))
