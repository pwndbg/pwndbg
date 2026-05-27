"""
Enables callbacks into functions to be automatically invoked
when various events occur to the debuggee (e.g. STOP on SIGINT)
by using a decorator.
"""

from __future__ import annotations

import functools
import sys
from collections import defaultdict
from collections import deque
from collections.abc import Callable
from functools import partial
from functools import wraps
from typing import Any
from typing import TypeVar

import gdb
from typing_extensions import ParamSpec

import pwndbg
import pwndbg.lib.config
from pwndbg import config
from pwndbg.color import message
from pwndbg.dbg_mod import EventHandlerPriority

DISABLED = "disabled"
DISABLED_DEADLOCK = "disabled-deadlock"
ENABLED = "enabled"

gdb_workaround_stop_event = config.add_param(
    "gdb-workaround-stop-event",
    DISABLED,
    "asynchronous stop events to improve 'commands' functionality",
    help_docstring=f"""
Note that this may cause unexpected behavior with Pwndbg or gdb.execute.

Values explained:

+ `{DISABLED}` - Disable the workaround (default).
+ `{DISABLED_DEADLOCK}` - Disable only deadlock detection; deadlocks may still occur.
+ `{ENABLED}` - Enable asynchronous stop events; gdb.execute may behave unexpectedly (asynchronously).
    """,
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=[DISABLED, DISABLED_DEADLOCK, ENABLED],
)

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
        self.registered: list[Callable[..., Any]] = []
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


# Monkeypatching GDB hihi
gdb.events.start = StartEvent()
gdb.events.suspend_all = object()


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


queued_events: deque[Callable[..., Any]] = deque()
executing_event = False
workaround_thread_conn = None


def _update_start_event_state(event_type: Any):
    """
    Update the state of the StartEvent appropriately
    (we emulate this event so we need to set it properly)
    """
    # Implement our custom event gdb.events.start!
    if event_type == gdb.events.stop:
        queued_events.append(gdb.events.start.on_stop)
    elif event_type == gdb.events.new_objfile:
        queued_events.append(gdb.events.start.on_new_objfile)
    elif event_type == gdb.events.exited:
        gdb.events.start.on_exited()


def _detect_deadlock():
    if not executing_event:
        # Not executing an event inside another event, so no deadlock
        return

    if gdb_workaround_stop_event == DISABLED_DEADLOCK:
        # Skip deadlock detection because this option disables it
        return

    print(message.error("DEADLOCK DETECTED..."))
    print(
        message.error(
            f"""The deadlock issue is likely caused by using 'commands[\\n]{
                message.hint("continue")
            }[\\n]end'.

To address this, you have three options:

1. Avoid using '{message.hint("commands")}'. Instead, rewrite it as a Python script. For example:
   {
                message.hint('''
   # Read more at: https://github.com/pwndbg/pwndbg/issues/425#issuecomment-892302716
   class Bp(gdb.Breakpoint):
       def stop(self):
           print("Breakpoint hit!")
           return False  # False = continue to next breakpoint, True = stop inferior

   Bp("main")
   ''')
            }

2. Replace '{message.hint("continue")}' with '{
                message.hint('pi gdb.execute("continue")')
            }' and use '{message.hint("set gdb-workaround-stop-event disabled-deadlock")}'.
   This change reduces the likelihood of deadlocks, while preserving pwndbg functionality.

3. Run '{message.hint("set gdb-workaround-stop-event enabled")}', allowing you to keep '{
                message.hint("continue")
            }' as is.
   However, this setting may cause pwndbg or gdb.execute to behave asynchronously/unpredictably.
"""
        )
    )
    sys.exit(1)


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
        global queued_events

        if not queued_events:
            return

        if not _is_safe_event_thread():
            gdb.post_event(_loop_until_thread_ok)
            return

        while queued_events:
            queued_events.popleft()()

    @wraps(event_handler)
    def _inner_handler(*a: P.args, **kw: P.kwargs):
        global queued_events, executing_event

        if event_type == gdb.events.start:
            # SKIP our custom event from this wrapper...
            event_handler(*a, **kw)
            return

        _detect_deadlock()
        _update_start_event_state(event_type)

        queued_events.append(lambda: event_handler(*a, **kw))
        if event_type == gdb.events.new_objfile and not _is_safe_event_packet():
            # Workaround to issue with gdbserver - Remote 'g' packet reply is too long
            # https://github.com/pwndbg/pwndbg/issues/2576
            gdb.post_event(_loop_until_thread_ok)
            return
        if event_type == gdb.events.stop:
            # Workaround to issue with gdb `commands \n continue \n end` - Selected thread is running
            # https://github.com/pwndbg/pwndbg/issues/425
            if gdb_workaround_stop_event == ENABLED:
                gdb.post_event(_loop_until_thread_ok)
                return

            executing_event = True
            gdb.execute("", to_string=True)  # Trigger bug in gdb, it is like 'yield'
            executing_event = False
        elif event_type in (gdb.events.cont, gdb.events.new_thread):
            # Workaround for crash in gdb when used: `target extended-remote` + `attach`
            # https://github.com/pwndbg/pwndbg/issues/3231
            global workaround_thread_conn
            conn = gdb.selected_inferior().connection
            if (
                isinstance(conn, gdb.RemoteTargetConnection)
                and conn.type == "extended-remote"
                and conn.is_valid()
                and workaround_thread_conn != conn
            ):
                gdb.selected_inferior().threads()[0].switch()
                workaround_thread_conn = conn

        while queued_events:
            queued_events.popleft()()

    return _inner_handler


# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
registered: dict[gdb.EventRegistry[Any], dict[EventHandlerPriority, list[Callable[..., None]]]] = {
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

# Keys are gdb.events.*
paused = defaultdict(bool)


def pause(event_registry: gdb.EventRegistry[Any]) -> None:
    paused[event_registry] = True


def unpause(event_registry: gdb.EventRegistry[Any]) -> None:
    paused[event_registry] = False


def event_handler_factory(
    event_registry: gdb.EventRegistry[Any], event_name: str, priority: EventHandlerPriority
) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """
    Essentially the implementation of pwndbg.dbg_mod.gdb.event_handler().

    Takes a gdb.EventRegistry because that contains some events that pwndbg.dbg_mod.EventType
    doesn't.

    Read the first few paragraphs of:
    https://sourceware.org/gdb/current/onlinedocs/gdb.html/Events-In-Python.html#Events-In-Python
    """

    def decorator(fn: Callable[..., None]) -> Callable[..., None]:
        # This is only executed once.

        if pwndbg.config.dev_debug_events:
            print("Connecting", fn.__name__, event_name)

        should_connect: bool = False

        if not registered[event_registry]:
            # We've never seen this type of event before.
            should_connect = True

        # Wrap the function for dev instrumentation
        @functools.wraps(fn)
        def _dev_wrapper(*a, **kw) -> None:
            if pwndbg.config.dev_debug_events:
                sys.stdout.write(
                    f"{event_name} ({priority.name}) {fn.__module__}.{fn.__qualname__}\n"
                )

            return fn(*a, **kw)

        # Register this event handler with us.
        registered[event_registry].setdefault(priority, []).append(_dev_wrapper)

        if should_connect:
            # We actually need to tell gdb to run `invoke_event` when
            # the appropriate event is invoked. Then inside `invoke_event`
            # we will call all `registered` functions.

            wrapped_invoke_event = partial(invoke_event, event_registry)
            wrapped_invoke_event = wrap_safe_event_handler(wrapped_invoke_event, event_registry)

            event_registry.connect(wrapped_invoke_event)

        return _dev_wrapper

    return decorator


def log_objfiles(ofile: gdb.NewObjFileEvent | None = None) -> None:
    if not (pwndbg.config.dev_debug_events and ofile):
        return

    name = ofile.new_objfile.filename

    print(f"objfile: {name!r}")
    gdb.execute("info sharedlibrary")
    return


gdb.events.new_objfile.connect(log_objfiles)


def invoke_event(event_registry: gdb.EventRegistry[Any], event_data: Any = None) -> None:
    """
    Invoke all registered handlers for a certain event_registry.
    event_data may be None if we manually ran this function.
    """
    if paused[event_registry] or paused[gdb.events.suspend_all]:
        return

    handlers = registered.get(event_registry)
    if handlers is None:
        return

    try:
        # Run all the event handlers for this event from lowest to highest priority.
        for prio in EventHandlerPriority:
            for func in handlers.get(prio, []):
                func()
    except Exception as e:
        import pwndbg.exception

        pwndbg.exception.handle()
        raise e


def after_reload(fire_start: bool = True) -> None:
    if gdb.selected_inferior().pid:
        invoke_event(gdb.events.stop)
        if fire_start:
            invoke_event(gdb.events.start)
        invoke_event(gdb.events.new_objfile)
        invoke_event(gdb.events.before_prompt)


def on_reload() -> None:
    for functions in registered.values():
        functions.clear()
