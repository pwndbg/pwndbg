#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Display the history.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import readline

import gdb

import pwndbg.commands

parser = argparse.ArgumentParser()
parser.description = __doc__
parser.add_argument('count', type=int, nargs='?',
                    help='The amount of history entries to display')
@pwndbg.commands.ArgparsedCommand(parser)
def history(count=10):
    history_length = readline.get_current_history_length()
    history = reversed([readline.get_history_item(i) for i in range(history_length)])
    history = list(history)[:min(count, history_length)]
    for entry in history:
        print(entry)
