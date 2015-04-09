import gdb
import traceback

debug = False
pause = 0

# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
on_stop        = []
on_new_objfile = []

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
    caller.name = func.__name__
    event_handler.connect(caller)
    return func

def exit(func):        return connect(func, gdb.events.exited, 'exit')
def cont(func):        return connect(func, gdb.events.cont, 'cont')
def new_objfile(func): return connect(func, gdb.events.new_objfile, 'obj')
def stop(func):        return connect(func, gdb.events.stop, 'stop')

