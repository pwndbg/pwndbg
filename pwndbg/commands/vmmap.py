#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command to print the vitual memory map a la /proc/self/maps.
"""
import gdb
import pwndbg.color
import pwndbg.commands
import pwndbg.vmmap


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def vmmap(map=None):
    """
    Print the virtal memory map
    """
    int_map = None
    str_map = None
    if isinstance(map, str):
        str_map = map
    elif isinstance(map, (long, int, gdb.Value)):
        int_map = int(map)

    print(pwndbg.color.legend())

    for page in pwndbg.vmmap.get():
        if str_map and str_map not in page.objfile:
            continue
        if int_map and int_map not in page:
            continue

        print(pwndbg.color.get(page.vaddr, text=str(page)))
