"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""

from __future__ import annotations

import pwndbg
import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("objfile", "start")
def is_remote() -> bool:
    return pwndbg.dbg.selected_inferior().is_remote()


def is_debug_probe() -> bool:
    """
    Returns True if the target is a debug probe for an embedded device.
    Currently detects the Black Magic Probe and the SEGGER J-Link GDB Server.
    """
    inferior = pwndbg.dbg.selected_inferior()
    # See https://github.com/pwndbg/pwndbg/pull/1439#issuecomment-1348477915 for the reason why we check the ouput like this.
    try:
        help_output = inferior.send_monitor("help")
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
        monitor_output = inferior.send_monitor("")
        return "Black Magic Probe" in monitor_output or "SEGGER J-Link GDB Server" in monitor_output
    except pwndbg.dbg_mod.Error:
        # SEGGER J-Link GDB Server and the Black Magic Probe should support the `monitor help` and `monitor` commands.
        return False
