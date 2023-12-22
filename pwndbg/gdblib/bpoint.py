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
