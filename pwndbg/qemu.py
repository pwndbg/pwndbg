#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Determine whether the target is being run under QEMU.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os

import gdb
import psutil

import pwndbg.events
import pwndbg.remote


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

@pwndbg.memoize.reset_on_stop
def is_qemu_kernel():
    return is_qemu() and not is_usermode()

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

@pwndbg.memoize.reset_on_start
def pid():
  """Find the PID of the qemu usermode binary which we are
  talking to.
  """
  # Find all inodes in our process which are connections.
  targets = set(c.raddr for c in psutil.Process().connections())

  # No targets? :(
  if not targets:
    return 0

  for process in psutil.process_iter():
    if not process.name().startswith('qemu'):
      continue

    try:
      connections = process.connections()
    except Exception:
      continue

    for c in connections:
      if c.laddr in targets:
        return process.pid
