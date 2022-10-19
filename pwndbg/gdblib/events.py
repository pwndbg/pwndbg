"""
Enables callbacks into functions to be automatically invoked
when various events occur to the debuggee (e.g. STOP on SIGINT)
by using a decorator.
"""

import sys
from functools import partial
from functools import wraps
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Set

import gdb

from pwndbg.gdblib.config import config

debug = config.add_param("debug-events", False, "display internal event debugging info")


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
class StartEvent:
    def __init__(self):
        self.registered = list()
        self.running = False

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
                sys.stdout.write("%r %s.%s\n" % ("start", function.__module__, function.__name__))
            function()

    def on_exited(self):
        self.running = False

    def on_stop(self):
        self.on_new_objfile()


gdb.events.start = StartEvent()


class EventWrapper:
    """
    Wrapper for GDB events which may not exist on older GDB versions but we still can
    fire them manually (to invoke them you have to call `invoke_callbacks`).
    """

    def __init__(self, name):
        self.name = name

        self._event = getattr(gdb.events, self.name, None)
        self._is_real_event = self._event is not None

    def connect(self, func):
        if self._event is not None:
            self._event.connect(func)

    def disconnect(self, func):
        if self._event is not None:
            self._event.disconnect(func)

    @property
    def is_real_event(self):
        return self._is_real_event

    def invoke_callbacks(self):
        """
        As an optimization please don't call this if your GDB has this event (check `.is_real_event`).
        """
        for f in registered[self]:
            f()


# Old GDBs doesn't have gdb.events.before_prompt, so we will emulate it using gdb.prompt_hook
before_prompt_event = EventWrapper("before_prompt")
gdb.events.before_prompt = before_prompt_event


# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
registered: Dict[Any, List[Callable]] = {
    gdb.events.exited: [],
    gdb.events.cont: [],
    gdb.events.new_objfile: [],
    gdb.events.stop: [],
    gdb.events.start: [],
    gdb.events.new_thread: [],
    gdb.events.before_prompt: [],  # The real event might not exist, but we wrap it
}

# GDB 7.9 and above only
try:
    registered[gdb.events.memory_changed] = []
    registered[gdb.events.register_changed] = []
except (NameError, AttributeError):
    pass


# When performing remote debugging, gdbserver is very noisy about which
# objects are loaded.  This greatly slows down the debugging session.
# In order to combat this, we keep track of which objfiles have been loaded
# this session, and only emit objfile events for each *new* file.
objfile_cache: Dict[str, Set[str]] = {}


def connect(func, event_handler, name=""):
    if debug:
        print("Connecting", func.__name__, event_handler)

    @wraps(func)
    def caller(*a):
        if debug:
            sys.stdout.write("%r %s.%s %r\n" % (name, func.__module__, func.__name__, a))

        if a and isinstance(a[0], gdb.NewObjFileEvent):
            objfile = a[0].new_objfile
            handler = "%s.%s" % (func.__module__, func.__name__)
            path = objfile.filename
            dispatched = objfile_cache.get(path, set())

            if handler in dispatched:
                return

            dispatched.add(handler)
            objfile_cache[path] = dispatched

        try:
            func()
        except Exception as e:
            import pwndbg.exception

            pwndbg.exception.handle()
            raise e

    registered[event_handler].append(caller)
    event_handler.connect(caller)
    return func


def exit(func):
    return connect(func, gdb.events.exited, "exit")


def cont(func):
    return connect(func, gdb.events.cont, "cont")


def new_objfile(func):
    return connect(func, gdb.events.new_objfile, "obj")


def stop(func):
    return connect(func, gdb.events.stop, "stop")


def start(func):
    return connect(func, gdb.events.start, "start")


def thread(func):
    return connect(func, gdb.events.new_thread, "thread")


before_prompt = partial(connect, event_handler=gdb.events.before_prompt, name="before_prompt")


def reg_changed(func):
    try:
        return connect(func, gdb.events.register_changed, "reg_changed")
    except AttributeError:
        return func


def mem_changed(func):
    try:
        return connect(func, gdb.events.memory_changed, "mem_changed")
    except AttributeError:
        return func


def log_objfiles(ofile=None):
    if not (debug and ofile):
        return

    name = ofile.new_objfile.filename

    print("objfile: %r" % name)
    gdb.execute("info sharedlibrary")


gdb.events.new_objfile.connect(log_objfiles)


def after_reload(start=True):
    if gdb.selected_inferior().pid:
        for f in registered[gdb.events.stop]:
            f()
        for f in registered[gdb.events.start]:
            if start:
                f()
        for f in registered[gdb.events.new_objfile]:
            f()
        for f in registered[gdb.events.before_prompt]:
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
    objfile_cache = dict()
