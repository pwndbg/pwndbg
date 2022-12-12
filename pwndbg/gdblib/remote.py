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
        help_output = gdb.execute("monitor help", to_string=True)
        if (
            "GDBserver" in help_output
            and "Black Magic Probe" not in help_output
            and "SEGGER J-Link GDB Server" not in help_output
        ):
            # We can't directly use the `monitor` command if we are using normal GDBserver, because the `monitor` command will cause GDBserver stuck.
            # So we check if we are using GDBserver by checking the output of `monitor help`.
            # TODO: Does this problem only occur with normal GDBserver?
            # If not, we should find a better way to check what remote server we are using.
            return False
    except gdb.error:
        # Now we check if we are using Black Magic Probe or the SEGGER J-Link GDB Server
        pass
    try:
        monitor_output = gdb.execute("monitor", to_string=True)
    except gdb.error:
        # the monitor command might fail, but we don't care since it doesn't fail on the devices we check for.
        return False
    return "Black Magic Probe" in monitor_output or "SEGGER J-Link GDB Server" in monitor_output
