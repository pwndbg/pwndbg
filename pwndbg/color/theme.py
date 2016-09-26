#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.config


class Parameter(pwndbg.config.Parameter):

    def __init__(self, name, default, docstring):
        super(Parameter, self).__init__(name,
                                        default,
                                        docstring,
                                        'theme')

class ColoredParameter(Parameter):

    def __init__(self, name, default, docstring):
        super(ColoredParameter, self).__init__(name,
                                               default,
                                               docstring)
