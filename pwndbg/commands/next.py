#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Stepping until an event occurs
"""

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def nextcall(*args):
