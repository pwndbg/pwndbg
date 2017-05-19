#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.which

readelf_path  = pwndbg.which.which("readelf")
checksec_path = pwndbg.which.which("checksec")
file_path     = pwndbg.which.which("file")


def OnlyWithFile(cmd):
    def _OnlyWithFile(function):
        def __OnlyWithFile(*args, **kwds):
            if not cmd:
                raise OSError('Could not find command %s in $PATH' %(function.__module__.split(".")[-1]))
            else:
                return function(*args, **kwds)
        return __OnlyWithFile
    return _OnlyWithFile