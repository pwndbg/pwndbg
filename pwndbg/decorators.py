#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools

first_prompt = False


def only_after_first_prompt(value_before=None):
    """
    Decorator to prevent a function from running before the first prompt was displayed.
    The 'value_before' parameter can be used to specify the value that is
    returned if the function is called before the first prompt was displayed.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if first_prompt:
                return func(*args, **kwargs)
            else:
                return value_before
        return wrapper
    return decorator
