"""
Determine whether the target is being run under QEMU.
"""

from __future__ import annotations

import pwndbg
import pwndbg.aglib.arch
import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("stop")
def is_qemu() -> bool:
    inferior = pwndbg.dbg.selected_inferior()
    if not inferior.is_remote():
        return False

    # Examples:
    #
    # pwndbg> maintenance packet Qqemu.sstepbits
    # sending: "Qqemu.sstepbits"
    # received: "ENABLE=1,NOIRQ=2,NOTIMER=4"
    #
    # pwndbg-lldb> process plugin packet send Qqemu.sstepbits
    #   packet: Qqemu.sstepbits
    # response: ENABLE=1,NOIRQ=2,NOTIMER=4
    #
    response = inferior.send_remote("Qqemu.sstepbits")

    return b"ENABLE=" in response


@pwndbg.lib.cache.cache_until("stop")
def is_usermode() -> bool:
    inferior = pwndbg.dbg.selected_inferior()
    if not inferior.is_remote():
        return False

    # There is also 'qAttached' - maybe we can use it too?
    # for qemu user though it returned "0"?
    # Try with:
    #    qemu-x86_64 -g 1234 `which ps`
    #    gdb -nx `which ps` -ex 'target remote :1234'
    response = inferior.send_remote("qOffsets")

    return b"Text=" in response


@pwndbg.lib.cache.cache_until("stop")
def is_qemu_usermode() -> bool:
    """Returns ``True`` if the target remote is being run under
    QEMU usermode emulation."""

    return is_qemu() and is_usermode()


@pwndbg.lib.cache.cache_until("stop")
def is_qemu_kernel() -> bool:
    return is_qemu() and not is_usermode()


def is_old_qemu_user() -> bool:
    # qemu-user <8.1
    return is_qemu_usermode() and not exec_file_supported()


@pwndbg.lib.cache.cache_until("stop")
def exec_file_supported() -> bool:
    """Returns ``True`` if the remote target understands the 'qXfer:exec-file:read' packet.
    A check for this feature is done in vmmap code, to warn against running legacy Qemu versions.
    """
    response = pwndbg.dbg.selected_inferior().send_remote("qSupported")

    return b"qXfer:exec-file:read" in response
