"""
Determine whether the target is being run under QEMU.
"""

from __future__ import annotations

import os

import psutil

import pwndbg
import pwndbg.aglib.arch
import pwndbg.lib.cache
from pwndbg.dbg import EventType


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

    return "ENABLE=" in response


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

    return "Text=" in response


@pwndbg.lib.cache.cache_until("stop")
def is_qemu_usermode() -> bool:
    """Returns ``True`` if the target remote is being run under
    QEMU usermode emulation."""

    return is_qemu() and is_usermode()


@pwndbg.lib.cache.cache_until("stop")
def is_qemu_kernel() -> bool:
    return is_qemu() and not is_usermode()


@pwndbg.lib.cache.cache_until("stop")
def exec_file_supported() -> bool:
    """Returns ``True`` if the remote target understands the 'qXfer:exec-file:read' packet.
    A check for this feature is done in vmmap code, to warn against running legacy Qemu versions.
    """
    response = pwndbg.dbg.selected_inferior().send_remote("qSupported")

    return "exec-file" in response


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.lib.cache.cache_until("stop")
def root() -> str | None:
    if not is_qemu_usermode():
        return None

    binfmt_root = f"/etc/qemu-binfmt/{pwndbg.aglib.arch.qemu}/"

    if not os.path.isdir(binfmt_root):
        return None

    pwndbg.dbg.set_sysroot(binfmt_root)

    return binfmt_root


@pwndbg.lib.cache.cache_until("start")
def pid() -> int:
    """Find the PID of the qemu usermode binary which we are
    talking to.
    """
    # Find all inodes in our process which are connections.
    targets = {c.raddr for c in psutil.Process().connections()}

    # No targets? :(
    if not targets:
        return 0

    for process in psutil.process_iter():
        if not process.name().startswith("qemu"):
            continue

        try:
            connections = process.connections()
        except Exception:
            continue

        for c in connections:
            if c.laddr in targets:
                return process.pid

    return 0
