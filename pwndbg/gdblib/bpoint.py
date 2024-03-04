from __future__ import annotations

from typing import Dict

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

    def stop(self) -> bool:
        # Clear the cache for the stop event.
        pwndbg.lib.cache.clear_cache("stop")
        return self.should_stop()

    def should_stop(self) -> bool:
        """
        This function is called whenever this breakpoint is hit in the code and
        its return value determines whether the inferior will be stopped.
        """
        return True


REGISTERED_BP_EVENTS: Dict[int, BreakpointEvent] = {}


class BreakpointEvent(gdb.Breakpoint):
    """
    Breakpoint class, similar to gdb.Breakpoint, but executes a given callback
    when, or very shortly after, a the breakpoint is hit, but does not stop
    the execution of the inferior.

    This allows us to execute code that changes the state of the inferior safely
    after a breakpoint is hit.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        REGISTERED_BP_EVENTS[id(self)] = self
        self.commands = (
            f"python pwndbg.gdblib.bpoint.REGISTERED_BP_EVENTS[{id(self)}].on_breakpoint_hit()"
        )

    def delete(self) -> None:
        del REGISTERED_BP_EVENTS[id(self)]
        super().delete()

    def on_breakpoint_hit(self) -> None:
        """
        This function is called whenever this breakpoint is hit in the code.
        """
        pass
