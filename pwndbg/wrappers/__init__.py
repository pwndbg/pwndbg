#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.which


class OnlyWithCommand(object):
    def __init__(self, func):
        self.func = func
        self.command = self.func.__module__.split(".")[-1]
        self.command_path = pwndbg.which.which(self.command)

    def __call__(self, *args, **kwargs):
        if self.command_path:
            return self.func(*args, **kwargs)
        else:
            raise OSError('Could not find command %s in $PATH' % self.command)

