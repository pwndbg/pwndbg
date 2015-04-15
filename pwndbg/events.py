#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Enables callbacks into functions to be automatically invoked
when various events occur to the debuggee (e.g. STOP on SIGINT)
by using a decorator.
"""
import traceback
import gdb

debug = False
pause = 0

# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
registered = {gdb.events.exited: [],
              gdb.events.cont: [],
              gdb.events.new_objfile: [],
              gdb.events.stop: []}

class Pause(object):
    def __enter__(self, *a, **kw):
        global pause
        pause += 1
    def __exit__(self, *a, **kw):
        global pause
        pause -= 1

def connect(func, event_handler, name=''):
    def caller(*a):
        func.__doc__
        if debug: print('%r %s.%s' % (name, func.__module__, func.__name__), a)
        if pause: return
        try:
            func()
        except Exception as e:
            if debug: print(traceback.format_exc())
            raise e
    registered[event_handler].append(caller)
    caller.name = func.__name__
    event_handler.connect(caller)
    return func

def exit(func):        return connect(func, gdb.events.exited, 'exit')
def cont(func):        return connect(func, gdb.events.cont, 'cont')
def new_objfile(func): return connect(func, gdb.events.new_objfile, 'obj')
def stop(func):        return connect(func, gdb.events.stop, 'stop')

def after_reload():
    return
    # if gdb.selected_inferior().pid:
    #     for f in registered[gdb.events.new_objfile]:
    #         f()
    #     for f in registered[gdb.events.stop]:
    #         f()


def on_reload():
    for event, functions in registered.items():
        for function in functions:
            event.disconnect(function)
        registered[event] = []
