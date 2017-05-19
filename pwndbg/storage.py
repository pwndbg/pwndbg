#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Provides persistent volatile and non-volatile storage of the results of
a function call.  Volatile storage uses the temporary directory, and is
generally cleared each reboot, or as the OS dictates.

Cached results are stored per-architecture, i.e. arm and i386 caches
are independent.  Cached results are also stored per-argument.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import inspect
import os
import pickle
import shelve
import tempfile
import time

import pwndbg.arch
import pwndbg.config

nonvolatile = pwndbg.config.Parameter('pwndbg-cache-nonvolatile', '~/.pwndbg', 'Non-volatile cache directory for Pwndbg storage')
volatile = pwndbg.config.Parameter('pwndbg-cache-volatile', tempfile.gettempdir(), 'Volatile cache directory for Pwndbg storage')

def name(function):
    mod_name = function.__module__
    func_name = function.__name__
    return mod_name + '.' + func_name

def path(function, directory=volatile):
    return os.path.join(str(directory), name(function))

class Cached(object):
    """Function decorator that persistently caches the results of the function it decorates."""
    function = None
    type = volatile
    shelf = None

    def __init__(self, function):
        self.function = function
        functools.update_wrapper(self, function)

    def __setup_shelf(self):
        """Deferred initialization allows customization of the paths by the user"""
        self.shelf = shelve.open(path(self.function, self.type),
                                 writeback=True,
                                 protocol=pickle.HIGHEST_PROTOCOL)

        # Set the creation time of the database, if it is not already set
        self.shelf.setdefault('create_time', time.time())

        # Get the modification time of the function's Python file
        function_mtime = os.path.getmtime(inspect.getfile(self.function))

        # If the file that the function is declared in is newer than
        # the database file, invalidate the cache.
        if self.shelf['create_time'] < function_mtime:
            self.shelf.clear()
            self.shelf['create_time'] = time.time()

    def __call__(self, *a, **kw):
        if self.shelf is None:
            self.__setup_shelf()

        # Cache per-architecture
        #
        # N.B.: This is important for a secondary reason:
        #       Shelve objects can only have keys which are strings.
        #       However, the inner objects can be ~= anything.
        arch = pwndbg.arch.current
        self.shelf.setdefault(arch, {})
        calls = self.shelf[arch]

        # Cache per-architecture x arguments
        args = inspect.getcallargs(self.function, *a, **kw)

        # Dict is not hashable, convert into a tuple so it can be a dictk ey
        args = tuple(sorted(args.iteritems()))

        # If we don't have this set of arguments so far...
        if args not in calls:
            calls[args] = self.function(*a, **kw)
            self.shelf[arch] = calls

        return self.shelf[arch][args]

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.function)

class NonVolatile(Cached):
    type = nonvolatile

class Volatile(Cached):
    type = volatile

# Example routines for testing
@Volatile
def demo(foo=0, bar=1, baz=2):
    time.sleep(3)
    return foo, bar, baz
