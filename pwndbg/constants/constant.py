#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Constant(int):
    def __new__(cls, s, i):
        obj = super(Constant, cls).__new__(cls, i)
        return obj
