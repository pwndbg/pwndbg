#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Enables callbacks into functions to be automatically invoked
when various events occur to the debuggee (e.g. STOP on SIGINT)
by using a decorator.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import sys
import traceback

import gdb

import pwndbg.color
import pwndbg.config
import pwndbg.stdio

debug = pwndbg.config.Parameter('debug-events', False, 'display internal event debugging info')
pause = 0


# There is no GDB way to get a notification when the binary itself
# is loaded from disk, by the operating system, before absolutely
# anything happens
#
# However, we get an Objfile event when the binary is loaded, before
# its entry point is invoked.
#
# We also get an Objfile event when we load up GDB, so we need
# to detect when the binary is running or not.
#
# Additionally, when attaching to a process running under QEMU, the
# very first event which is fired is a 'stop' event.  We need to
# capture this so that we can fire off all of the 'start' events first.
class StartEvent(object):
    def __init__(self):
        self.registered = list()
        self.running    = False
    def connect(self, function):
        if function not in self.registered:
            self.registered.append(function)
    def disconnect(self, function):
        if function in self.registered:
            self.registered.remove(function)
    def on_new_objfile(self):
        if self.running or not gdb.selected_thread():
            return

        self.running = True

        for function in self.registered:
            if debug:
                sys.stdout.write('%r %s.%s\n' % ('start', function.__module__, function.__name__))
            function()

    def on_exited(self):
        self.running = False

    def on_stop(self):
        self.on_new_objfile()

gdb.events.start = StartEvent()

# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
registered = {gdb.events.exited: [],
              gdb.events.cont: [],
              gdb.events.new_objfile: [],
              gdb.events.stop: [],
              gdb.events.start: []}

# GDB 7.9 and above only
try:
    registered[gdb.events.memory_changed] = []
    registered[gdb.events.register_changed] = []
except (NameError, AttributeError):
    pass

class Pause(object):
    def __enter__(self, *a, **kw):
        global pause
        pause += 1
    def __exit__(self, *a, **kw):
        global pause
        pause -= 1

# When performing remote debugging, gdbserver is very noisy about which
# objects are loaded.  This greatly slows down the debugging session.
# In order to combat this, we keep track of which objfiles have been loaded
# this session, and only emit objfile events for each *new* file.
objfile_cache = set()

def connect(func, event_handler, name=''):
    if debug:
        print("Connecting", func.__name__, event_handler)

    @functools.wraps(func)
    def caller(*a):
        if debug:
            sys.stdout.write('%r %s.%s %r\n' % (name, func.__module__, func.__name__, a))

        if a and isinstance(a[0], gdb.NewObjFileEvent):
            objfile = a[0].new_objfile
            path = objfile.filename

            if path in objfile_cache:
                return

            # print(path, objfile.is_valid())

            objfile_cache.add(path)

        if pause: return
        with pwndbg.stdio.stdio:
            try:
                func()
            except Exception as e:
                msg = "Exception during func={}.{} {!r}".format(func.__module__, func.__name__, a)
                msg = pwndbg.color.red(msg)
                print(msg, file=sys.stderr)
                traceback.print_exc()
                raise e

    registered[event_handler].append(caller)
    event_handler.connect(caller)
    return func

def exit(func):        return connect(func, gdb.events.exited, 'exit')
def cont(func):        return connect(func, gdb.events.cont, 'cont')
def new_objfile(func): return connect(func, gdb.events.new_objfile, 'obj')
def stop(func):        return connect(func, gdb.events.stop, 'stop')
def start(func):       return connect(func, gdb.events.start, 'start')
def reg_changed(func):
    try:
        return connect(func, gdb.events.register_changed, 'reg_changed')
    except Exception:
        return func
def mem_changed(func):
    try:
        return connect(func, gdb.events.memory_changed, 'mem_changed')
    except Exception:
        return func

def log_objfiles(ofile=None):
    if not (debug and ofile):
        return

    name = ofile.new_objfile.filename

    print("objfile: %r" % name)
    gdb.execute('info sharedlibrary')

gdb.events.new_objfile.connect(log_objfiles)

def after_reload(start=True):
    if gdb.selected_inferior().pid:
        for f in registered[gdb.events.stop]:
            f()
        for f in registered[gdb.events.start]:
            if start: f()
        for f in registered[gdb.events.new_objfile]:
            f()

def on_reload():
    for event, functions in registered.items():
        for function in functions:
            event.disconnect(function)
        registered[event] = []

@new_objfile
def _start_newobjfile():
    gdb.events.start.on_new_objfile()

@exit
def _start_exit():
    gdb.events.start.on_exited()

@stop
def _start_stop():
    gdb.events.start.on_stop()

@exit
def _reset_objfiles():
    global objfile_cache
    objfile_cache = set()
