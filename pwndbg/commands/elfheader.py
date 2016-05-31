#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb
import pwndbg.commands

@pwndbg.commands.Command
def elfheader():
    """
    Prints the section mappings contained in the ELF header
    """
    gdb.execute('info files')
