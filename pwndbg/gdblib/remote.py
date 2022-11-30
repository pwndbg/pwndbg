"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""

import gdb

import pwndbg.lib.memoize


@pwndbg.lib.memoize.reset_on_objfile
@pwndbg.lib.memoize.reset_on_start
def is_remote():
    # Example:
    # pwndbg> maintenance print target-stack
    # The current target stack is:
    #   - remote (Remote serial target in gdb-specific protocol)
    #   - exec (Local exec file)
    #   - None (None)
    return "remote" in gdb.execute("maintenance print target-stack", to_string=True)


def is_debug_probe():
    """
    Returns True if the target is a debug probe for an embedded device.
    Currently detects the Black Magic Probe and the SEGGER J-Link GDB Server.
    """
    try:
        monitor_output = gdb.execute("monitor", to_string=True)
    except gdb.error:
        # the monitor command might fail, but we don't care since it doesn't fail on the devices we check for.
        return False
    return "Black Magic Probe" in monitor_output or "SEGGER J-Link GDB Server" in monitor_output
