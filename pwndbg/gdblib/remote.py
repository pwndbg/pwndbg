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
    # See https://github.com/pwndbg/pwndbg/pull/1439#issuecomment-1348477915 for the reason why we check the ouput like this.
    try:
        help_output = gdb.execute("monitor help", to_string=True)
        if "Quit GDBserver\n" in help_output:
            # We can't use the `monitor` command directly when using normal GDBserver because it can cause GDBserver somehow show an additional newline in the end and fail to show the context because `pwndbg.gdblib.proc.thread_is_stopped` is False when running `gdb.prompt_hook`.
            # To avoid this issue, we can check the output of `monitor help` to determine if we're using GDBserver.
            # The output on normal GDBserver looks like this:
            # pwndbg> monitor help
            # The following monitor commands are supported:
            #   set debug <0|1>
            #     Enable general debugging messages
            #   set debug-hw-points <0|1>
            #     Enable h/w breakpoint/watchpoint debugging messages
            #   set remote-debug <0|1>
            #     Enable remote protocol debugging messages
            #   set event-loop-debug <0|1>
            #     Enable event loop debugging messages
            #   set debug-format option1[,option2,...]
            #     Add additional information to debugging messages
            #     Options: all, none, timestamp
            #   exit
            #     Quit GDBserver
            # TODO/FIXME: Investigate the cause of this problem and fix it properly.
            # TODO/FIXME: Determine if this issue only occurs with normal GDBserver and find a better way to check the remote server if necessary.
            return False
        elif "SEGGER J-Link GDB Server" in help_output:
            return True
        monitor_output = gdb.execute("monitor", to_string=True)
        return "Black Magic Probe" in monitor_output or "SEGGER J-Link GDB Server" in monitor_output
    except gdb.error:
        # SEGGER J-Link GDB Server and the Black Magic Probe should support the `monitor help` and `monitor` commands.
        return False
