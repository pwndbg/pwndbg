from __future__ import annotations

import gdb

import pwndbg.lib.cache


class Breakpoint(gdb.Breakpoint):
    """
    Breakpoint class, similar to gdb.Breakpoint, but clears the caches
    associated with the stop event before determining whether it should stop the
    inferior or not.

    Unlike gdb.Breakpoint, users of this class should override `should_stop()`,
    instead of `stop()`, as the latter is used to do cache invalidation.
    """

    def stop(self):
        # Clear the cache for the stop event.
        pwndbg.lib.cache.clear_cache("stop")
        return self.should_stop()

    def should_stop(self):
        """
        This function is called whenever this breakpoint is hit in the code and
        its return value determines whether the inferior will be stopped.
        """
        return True


REGISTERED_BP_EVENTS = set()


class BreakpointEvent(gdb.Breakpoint):
    """
    Breakpoint class, similar to gdb.Breakpoint, but executes a given callback
    when, or very shortly after, a the breakpoint is hit, but does not stop
    the execution of the inferior.

    This allows us to execute code that changes the state of the inferior safely
    after a breakpoint is hit.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        REGISTERED_BP_EVENTS.add(id(self))

    def delete(self):
        REGISTERED_BP_EVENTS.remove(id(self))
        super().delete()

    def on_breakpoint_hit(self):
        """
        This function is called whenever this breakpoint is hit in the code.
        """
        pass


# Attatch ourselves to the event runtime so that we can fire the
# on_breakpoint_hit() function for all of the breakpoint events that stopped on
# a given piece of code.
def _handle_stop(event):
    if type(event) is not gdb.BreakpointEvent:
        # We have nothing to do here.
        return

    print("Handling BPStop")
    should_continue = True
    for bp in event.breakpoints:
        if id(bp) not in REGISTERED_BP_EVENTS:
            # This breakpoint does not belong to us. We also can't automatically
            # resume execution after we finish processing our events, because
            # someone else expects the code to stop here.
            should_continue = False
            continue
        bp.on_breakpoint_hit()
    if should_continue:
        gdb.execute("continue")


gdb.events.stop.connect(_handle_stop)
