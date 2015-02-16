import gdb

debug = True

def connect(func, event_handler):
    def caller(*a):
        func.__doc__
        if debug: print('%s.%s' % (func.__module__, func.__name__), a)
        try:
            func()
        except Exception as e:
            print("Exception occurred", e)
            raise e
    caller.name = func.__name__
    event_handler.connect(caller)
    return func

def exit(func):        return connect(func, gdb.events.exited)
def cont(func):        return connect(func, gdb.events.cont)
def new_objfile(func): return connect(func, gdb.events.new_objfile)
def stop(func):        return connect(func, gdb.events.stop)
