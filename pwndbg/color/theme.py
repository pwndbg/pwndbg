#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
