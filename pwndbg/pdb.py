#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module serves as utility for the developers to get pdb debugging session right, whenever standard:
    import pdb; pdb.set_trace()
Can't do its job properly (that happens often as gdb does some magic with stdout/stderr).

Thanks to Dmoreno: http://stackoverflow.com/questions/17074177/how-to-debug-python-cli-that-takes-stdin

Usage:
    import pwndbg.pdb

Importing the module will print out pretty message on what to do next.
"""
import functools
import pdb
import os

import pwndbg.stdio

for name, value in list(pdb.__dict__.items()):
	if not callable(value):
		continue

	@functools.wraps(value)
	def wrapper(*a, **kw):
		with pwndbg.stdio.stdio:
			return value(*a, **kw)

	setattr(pdb, name, value)