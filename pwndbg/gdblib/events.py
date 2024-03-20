"""
Enables callbacks into functions to be automatically invoked
when various events occur to the debuggee (e.g. STOP on SIGINT)
by using a decorator.
"""

from __future__ import annotations

import sys
from functools import partial
from functools import wraps
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Set
from typing import TypeVar

import gdb
from typing_extensions import ParamSpec

from pwndbg.gdblib.config import config

debug = config.add_param("debug-events", False, "display internal event debugging info")

P = ParamSpec("P")
T = TypeVar("T")


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
    def __init__(self) -> None:
        self.registered: List[Callable[..., Any]] = []
        self.running = False

    def connect(self, function: Callable[..., Any]) -> None:
        if function not in self.registered:
            self.registered.append(function)

    def disconnect(self, function: Callable[..., Any]) -> None:
        if function in self.registered:
            self.registered.remove(function)

    def on_new_objfile(self) -> None:
        if self.running or not gdb.selected_thread():
            return

        self.running = True

        for function in self.registered:
            if debug:
                sys.stdout.write(
                    "{!r} {}.{}\n".format("start", function.__module__, function.__name__)
                )
            function()

    def on_exited(self) -> None:
        self.running = False

    def on_stop(self) -> None:
        self.on_new_objfile()


gdb.events.start = StartEvent()

# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
registered: Dict[Any, List[Callable[..., Any]]] = {
    gdb.events.exited: [],
    gdb.events.cont: [],
    gdb.events.new_objfile: [],
    gdb.events.stop: [],
    gdb.events.start: [],
    gdb.events.new_thread: [],
    gdb.events.before_prompt: [],  # The real event might not exist, but we wrap it
    gdb.events.memory_changed: [],
    gdb.events.register_changed: [],
}


# When performing remote debugging, gdbserver is very noisy about which
# objects are loaded.  This greatly slows down the debugging session.
# In order to combat this, we keep track of which objfiles have been loaded
# this session, and only emit objfile events for each *new* file.
objfile_cache: Dict[str, Set[str]] = {}


def connect(func: Callable[P, T], event_handler: Any, name: str = "") -> Callable[P, T]:
    if debug:
        print("Connecting", func.__name__, event_handler)

    @wraps(func)
    def caller(*a: P.args, **kw: P.kwargs) -> None:
        if debug:
            sys.stdout.write(f"{name!r} {func.__module__}.{func.__name__} {a!r}\n")

        if a and isinstance(a[0], gdb.NewObjFileEvent):
            objfile = a[0].new_objfile
            handler = f"{func.__module__}.{func.__name__}"
            path = objfile.filename
            dispatched = objfile_cache.get(path, set())

            if handler in dispatched:
                return None

            dispatched.add(handler)
            objfile_cache[path] = dispatched

        try:
            # Don't pass the event along to the decorated function.
            # This is because there are functions with multiple event decorators
            func()
        except Exception as e:
            import pwndbg.exception

            pwndbg.exception.handle()
            raise e

    registered[event_handler].append(caller)
    event_handler.connect(caller)
    return func


def exit(func: Callable[[], T]) -> Callable[[], T]:
    return connect(func, gdb.events.exited, "exit")


def cont(func: Callable[[], T]) -> Callable[[], T]:
    return connect(func, gdb.events.cont, "cont")


def new_objfile(func: Callable[[], T]) -> Callable[[], T]:
    return connect(func, gdb.events.new_objfile, "obj")


def stop(func: Callable[[], T]) -> Callable[[], T]:
    return connect(func, gdb.events.stop, "stop")


def start(func: Callable[[], T]) -> Callable[[], T]:
    return connect(func, gdb.events.start, "start")


def thread(func: Callable[[], T]) -> Callable[[], T]:
    return connect(func, gdb.events.new_thread, "thread")


before_prompt = partial(connect, event_handler=gdb.events.before_prompt, name="before_prompt")


def reg_changed(func: Callable[[], T]) -> Callable[[], T]:
    try:
        return connect(func, gdb.events.register_changed, "reg_changed")
    except AttributeError:
        return func


def mem_changed(func: Callable[[], T]) -> Callable[[], T]:
    try:
        return connect(func, gdb.events.memory_changed, "mem_changed")
    except AttributeError:
        return func


def log_objfiles(ofile: gdb.NewObjFileEvent | None = None) -> None:
    if not (debug and ofile):
        return None

    name = ofile.new_objfile.filename

    print("objfile: %r" % name)
    gdb.execute("info sharedlibrary")
    return None


gdb.events.new_objfile.connect(log_objfiles)


def after_reload(start: bool = True) -> None:
    if gdb.selected_inferior().pid:
        if gdb.events.stop in registered:
            for f in registered[gdb.events.stop]:
                f()
        if gdb.events.start in registered:
            for f in registered[gdb.events.start]:
                if start:
                    f()
        if gdb.events.new_objfile in registered:
            for f in registered[gdb.events.new_objfile]:
                f()
        if gdb.events.before_prompt in registered:
            for f in registered[gdb.events.before_prompt]:
                f()


def on_reload() -> None:
    for event, functions in registered.items():
        for function in functions:
            event.disconnect(function)
        registered[event] = []


@new_objfile
def _start_newobjfile() -> None:
    gdb.events.start.on_new_objfile()


@exit
def _start_exit() -> None:
    gdb.events.start.on_exited()


@stop
def _start_stop() -> None:
    gdb.events.start.on_stop()


@exit
def _reset_objfiles() -> None:
    global objfile_cache
    objfile_cache = {}
