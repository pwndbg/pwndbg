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
            # We can't use the `monitor` command directly when using normal GDBserver because it can cause GDBserver somehow show an additional newline in the end and fail to show the context because `pwndbg.gdblib.proc.thread_is_stopped` is False when running `gdb.prompt_hook`.
            # To avoid this issue, we can check the output of `monitor help` to determine if we're using GDBserver.
            # TODO/FIXME: Investigate the cause of this problem and fix it properly.
            # TODO/FIXME: Determine if this issue only occurs with normal GDBserver and find a better way to check the remote server if necessary.
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
