#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class Constant(int):
    def __new__(cls, s, i):
        obj = super(Constant, cls).__new__(cls, i)
        return obj
