#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import pwndbg.which

class OnlyWithCommand(object):
    def __init__(self, command):
        self.cmd_name = command
        self.cmd_path = pwndbg.which.which(command)

    def __call__(self, function):
        function.cmd_path = self.cmd_path

        @functools.wraps(function)
        def _OnlyWithCommand(*a,**kw):
            if self.cmd_path:
                return function(*a, **kw)
            else:
                raise OSError('Could not find command %s in $PATH' % self.cmd_name)
        return _OnlyWithCommand

