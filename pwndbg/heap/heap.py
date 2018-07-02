#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.events
import pwndbg.symbol


class BaseHeap(object):
    """Heap abstraction layer."""

    def breakpoint(event):
        """Enables breakpoints on the specific event.

        Arguments:
            event(str): One of 'alloc','realloc','free'

        Returns:
            A gdb.Breakpoint object.
        """
        raise NotImplementedError()

    def summarize(address, **kwargs):
        """Returns a textual summary of the specified address.

        Arguments:
            address(int): Address of the heap block to summarize.

        Returns:
            A string.
        """
        raise NotImplementedError()

    def containing(address):
        """Returns the address of the allocation which contains 'address'.

        Arguments:
            address(int): Address to look up.

        Returns:
            An integer.
        """
        raise NotImplementedError()


    def is_initialized(self):
        """Returns whether the allocator is initialized or not.

        Returns:
            A boolean.
        """
        raise NotImplementedError()
