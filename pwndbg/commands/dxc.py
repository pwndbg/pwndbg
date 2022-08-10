#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import gdb

import pwndbg.arch
import pwndbg.commands
import pwndbg.memory
from pwndbg.commands.windbg import get_type


def create_argparser(size):
    parser = argparse.ArgumentParser(description="Starting at the specified address, dump N %s as code." % (size))
    parser.add_argument("address", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from.")
    parser.add_argument("count", type=pwndbg.commands.AddressExpr, default=64, nargs="?", help="The number of %s to dump." % (size))
    parser.add_argument("--language", type=str, choices=["c", "py"], default=None, nargs="?", help="The language syntax to use")
    return parser


@pwndbg.commands.ArgparsedCommand(create_argparser("bytes"))
@pwndbg.commands.OnlyWhenRunning
def dbc(address, count=64, language=None):
    """
    Starting at the specified address, dump N bytes as code(default 64).
    """
    dXc(1, address, count, language)


@pwndbg.commands.ArgparsedCommand(create_argparser("words"))
@pwndbg.commands.OnlyWhenRunning
def dwc(address, count=32, language=None):
    """
    Starting at the specified address, dump N words as code(default 32).
    """
    dXc(2, address, count, language)


@pwndbg.commands.ArgparsedCommand(create_argparser("dwords"))
@pwndbg.commands.OnlyWhenRunning
def ddc(address, count=16, language=None):
    """
    Starting at the specified address, dump N dwords as code(default 16).
    """
    dXc(4, address, count, language)


@pwndbg.commands.ArgparsedCommand(create_argparser("qwords"))
@pwndbg.commands.OnlyWhenRunning
def dqc(address, count=8, language=None):
    """
    Starting at the specified address, dump N qwords as code(default 8).
    """
    dXc(8, address, count, language)


def dXc(size, address, count, lang):
    print_header(size, lang)
    print_array(size, address, count)
    print_footer(size, lang)


def print_header(size, lang):
    if lang == "c":
        print("uint{}_t data[] = {{".format(size*8))
    elif lang == "py":
        print("data = [")


def print_footer(size, lang):
    if lang == "c":
        print("};")
    elif lang == "py":
        print("]")


def print_array(size, address, count):
    gdb_type = get_type(size)

    first = True
    for i in range(count):
        try:
            raw_value = int(pwndbg.memory.poi(gdb_type, address + i * size))
            value = '0x{:0{padding}x}'.format(raw_value, padding=size*2)
            if first:
                print(value, end="")
                first = False
            else:
                print(", " + ("\n" if (i + 16) % 16 == 0 else "") + value, end="")
        except gdb.MemoryError:
            break

    print("")
