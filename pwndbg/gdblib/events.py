"""
Enables callbacks into functions to be automatically invoked
when various events occur to the debuggee (e.g. STOP on SIGINT)
by using a decorator.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from collections import deque
from enum import Enum
from enum import auto
from functools import partial
from functools import wraps
from typing import Any
from typing import Callable
from typing import Deque
from typing import Dict
from typing import List
from typing import TypeVar

import gdb
from typing_extensions import ParamSpec

from pwndbg import config

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
            function()

    def on_exited(self) -> None:
        self.running = False

    def on_stop(self) -> None:
        self.on_new_objfile()


gdb.events.start = StartEvent()


def _is_safe_event_packet():
    try:
        gdb.selected_frame()
    except gdb.error as e:
        if "Remote 'g' packet reply is too long" in str(e):
            return False
    return True


def _is_safe_event_thread():
    try:
        gdb.newest_frame()
    except gdb.error as e:
        if "Selected thread is running" in str(e):
            return False
    return True


queued_invalid_events: Deque[Callable[..., Any]] = deque()


def wrap_safe_event_handler(event_handler: Callable[P, T], event_type: Any) -> Callable[P, T]:
    """
    Wraps an event handler to ensure it is only executed when the event is safe.
    Invalid events are queued and executed later when safe.

    Note: Avoid using `gdb.post_event` because of another bug in gdbserver
    where the `gdb.newest_frame` function may not work properly.

    Workaround to fix bug in gdbserver (gdb.events.new_objfile): https://github.com/pwndbg/pwndbg/issues/2576
    Workaround to fix bug in gdb (gdb.events.stop): https://github.com/pwndbg/pwndbg/issues/425
    """

    def _loop_until_thread_ok():
        global queued_invalid_events

        if not queued_invalid_events:
            return

        if not _is_safe_event_thread():
            gdb.post_event(_loop_until_thread_ok)
            return

        while queued_invalid_events:
            queued_invalid_events.popleft()()

    @wraps(event_handler)
    def _inner_handler(*a: P.args, **kw: P.kwargs):
        global queued_invalid_events

        # Implement our custom event gdb.events.start!
        if event_type == gdb.events.new_objfile:
            queued_invalid_events.append(lambda: gdb.events.start.on_new_objfile())
        elif event_type == gdb.events.exited:
            gdb.events.start.on_exited()
        elif event_type == gdb.events.stop:
            gdb.post_event(gdb.events.start.on_stop)

        # Workaround to bugs in GDB...
        if event_type == gdb.events.new_objfile and not _is_safe_event_packet():
            # Workaround to issue with gdbserver - Remote 'g' packet reply is too long
            # https://github.com/pwndbg/pwndbg/issues/2576
            queued_invalid_events.append(lambda: event_handler(*a, **kw))
            gdb.post_event(_loop_until_thread_ok)
            return
        elif event_type == gdb.events.stop:
            # Workaround to issue with gdb `commands \n continue \n end` - Selected thread is running
            # https://github.com/pwndbg/pwndbg/issues/425
            queued_invalid_events.append(lambda: event_handler(*a, **kw))
            gdb.post_event(_loop_until_thread_ok)
            return
        else:
            # events safe to execute!
            while queued_invalid_events:
                queued_invalid_events.popleft()()
            event_handler(*a, **kw)

    return _inner_handler


class HandlerPriority(Enum):
    """
    A priority level for an event handler, ordered from highest to lowest priority.
    """

    CACHE_CLEAR = auto()
    LOW = auto()


# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
registered: Dict[Any, Dict[HandlerPriority, List[Callable[..., Any]]]] = {
    gdb.events.exited: {},
    gdb.events.cont: {},
    gdb.events.new_objfile: {},
    gdb.events.stop: {},
    gdb.events.start: {},
    gdb.events.new_thread: {},
    gdb.events.before_prompt: {},  # The real event might not exist, but we wrap it
    gdb.events.memory_changed: {},
    gdb.events.register_changed: {},
}

# Registered events are wrapped and aren't directly connected to GDB
# This is a map from event to the actual handler connected to GDB
connected = {}

# Keys are gdb.events.*
paused = defaultdict(bool)


def pause(event_registry) -> None:
    paused[event_registry] = True


def unpause(event_registry) -> None:
    paused[event_registry] = False


def connect(
    func: Callable[[], T],
    event_handler: Any,
    name: str = "",
    priority: HandlerPriority = HandlerPriority.LOW,
) -> Callable[[], T]:
    if debug:
        print("Connecting", func.__name__, event_handler)

    @wraps(func)
    def caller(*a: P.args, **kw: P.kwargs) -> None:
        if paused[event_handler]:
            return None

        if debug:
            sys.stdout.write(f"{name!r} {func.__module__}.{func.__name__} {a!r}\n")

        try:
            # Don't pass the event along to the decorated function.
            # This is because there are functions with multiple event decorators
            func()
        except Exception as e:
            import pwndbg.exception

            pwndbg.exception.handle()
            raise e

    registered[event_handler].setdefault(priority, []).append(caller)
    if event_handler not in connected:
        handle = partial(invoke_event, event_handler)
        handle = wrap_safe_event_handler(handle, event_handler)

        event_handler.connect(handle)
        connected[event_handler] = handle
    return func


def exit(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.exited, "exit", **kwargs)


def cont(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.cont, "cont", **kwargs)


def new_objfile(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.new_objfile, "obj", **kwargs)


def stop(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.stop, "stop", **kwargs)


def start(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.start, "start", **kwargs)


def thread(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.new_thread, "thread", **kwargs)


def before_prompt(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.before_prompt, "before_prompt", **kwargs)


def reg_changed(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.register_changed, "reg_changed", **kwargs)


def mem_changed(func: Callable[[], T], **kwargs: Any) -> Callable[[], T]:
    return connect(func, gdb.events.memory_changed, "mem_changed", **kwargs)


def log_objfiles(ofile: gdb.NewObjFileEvent | None = None) -> None:
    if not (debug and ofile):
        return None

    name = ofile.new_objfile.filename

    print("objfile: %r" % name)
    gdb.execute("info sharedlibrary")
    return None


gdb.events.new_objfile.connect(log_objfiles)


# invoke all registered handlers of a certain event type
def invoke_event(event: Any, *args: Any, **kwargs: Any) -> None:
    handlers = registered.get(event)
    if handlers is not None:
        for prio in HandlerPriority:
            for f in handlers.get(prio, []):
                f(*args, **kwargs)


def after_reload(start: bool = True) -> None:
    if gdb.selected_inferior().pid:
        invoke_event(gdb.events.stop)
        invoke_event(gdb.events.start)
        invoke_event(gdb.events.new_objfile)
        invoke_event(gdb.events.before_prompt)


def on_reload() -> None:
    for functions in registered.values():
        functions.clear()
