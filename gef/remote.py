#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb

def is_remote():
    return 'serial line' in gdb.execute('info program',to_string=True)