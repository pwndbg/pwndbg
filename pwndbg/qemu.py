#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Determine whether the target is being run under QEMU.
"""
import gdb
import os

import pwndbg.remote
import pwndbg.events

@pwndbg.memoize.reset_on_stop
def is_qemu():
    if not pwndbg.remote.is_remote():
        return False

    response = gdb.execute('maintenance packet Qqemu.sstepbits', 
                           to_string=True,
                           from_tty=False)

    return 'ENABLE=' in response

@pwndbg.memoize.reset_on_stop
def is_usermode():
    if not pwndbg.remote.is_remote():
        return False


    # If we had QEMU 2.4 or better, we could use
    #
    #    maintenance packet QAttached:
    #
    # However, Ubuntu 14 still has QEMU 2.2, so we have to use
    # a different command as a heuristic.
    response = gdb.execute('maintenance packet QOffsets', 
                           to_string=True,
                           from_tty=False)


    return 'Text=' in response

@pwndbg.memoize.reset_on_stop
def is_qemu_usermode():
    """Returns ``True`` if the target remote is being run under
    QEMU usermode emulation."""

    return is_qemu() and is_usermode()

@pwndbg.events.start
@pwndbg.memoize.reset_on_stop
def root():
  global root

  if not is_qemu_usermode():
    return

  binfmt_root = '/etc/qemu-binfmt/%s/' % pwndbg.arch.qemu

  if not os.path.isdir(binfmt_root):
    return

  gdb.execute('set sysroot ' + binfmt_root,
              from_tty=False)

  return binfmt_root