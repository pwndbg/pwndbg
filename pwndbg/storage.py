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

nonvolatile = pwndbg.config.Parameter('pwndbg-cache-nonvolatile', os.path.expanduser('~/.pwndbg'), 'Non-volatile cache directory for Pwndbg storage')
volatile = pwndbg.config.Parameter('pwndbg-cache-volatile', tempfile.gettempdir(), 'Volatile cache directory for Pwndbg storage')

# Ensure there is only one Shelf instance per database, so that
# we don't get weird things with multiple instances / concurrent writes / etc.
shelves = {
    nonvolatile: None,
    volatile: None
}

@pwndbg.config.Trigger([volatile, nonvolatile])
def update():
    global shelves

    for db in (volatile, nonvolatile):
        database_path = os.path.join(str(db), 'storage')

        # Ensure the path exists, then open the database
        if not os.path.isdir(database_path):
            os.makedirs(database_path)

        shelves[db] = shelve.open(database_path,
                                  writeback=True,
                                  protocol=pickle.HIGHEST_PROTOCOL)

# Perform manual update to initialize the values
update()

class Cached(object):
    """Function decorator that persistently caches the results of the function it decorates."""

    def __init__(self, function, type):
        self.function = function
        self.function_name = function.__module__ + '.' + function.__name__
        self.type = Type
        functools.update_wrapper(self, function)

    @property
    def shelf(self):
        return shelves[self.type]

    @property
    def calls(self):
        return shelves[self.type][self.function_name]

    @property
    def initialized(self):
        return self.function_name in self.shelf and 'create_time' in self.calls


    def __setup_shelf(self):
        """Deferred initialization allows customization of the paths by the user"""

        # Create an empty dictionary for this function if nothing exists
        self.shelf.setdefault(self.function_name, {})

        # Get the modification time of the function's Python file
        try:
            function_mtime = os.path.getmtime(inspect.getfile(self.function))
        except Exception:
            # If the function is from the repl, the path will be e.g. <stdin>
            function_mtime = 999999999999999999999

        # Find out when the cache for this function was created
        create_time = self.calls.get('create_time', 0)

        # If the file is newer than the cache, nuke the cache
        if create_time < function_mtime:
            self.calls.clear()
            create_time = time.time()

        self.calls['create_time'] = create_time

    def __call__(self, *a, **kw):
        # Initialize the database if needed
        if not self.initialized:
            self.__setup_shelf()

        # Get the name/value for every argument passed to the function
        args = inspect.getcallargs(self.function, *a, **kw)

        # Add the architecture to the arguments, so that we don't accidentally
        # cache e.g. ARM results for an i386 binary.
        args['pwndbg.arch.current'] = pwndbg.arch.current

        # Dict is not hashable, convert into a tuple so it can be a dict key
        args = tuple(sorted(args.items()))

        # If we don't have this set of arguments so far...
        if args not in self.calls:
            result = self.calls[args] = self.function(*a, **kw)

            # Save the new data
            self.shelf.sync()

        # Extract the return value from storage
        retval = self.calls[args]


        return retval

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.function)

class NonVolatile(Cached):
    def __init__(self, function):
        super(NonVolatile, self).__init__(function, nonvolatile)

class Volatile(Cached):
    def __init__(self, function):
        super(NonVolatile, self).__init__(function, volatile)

# Example routines for testing
@Volatile
def demo(foo=0, bar=1, baz=2):
    time.sleep(3)
    return foo, bar, baz

