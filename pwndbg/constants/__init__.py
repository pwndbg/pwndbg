#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.arch

from . import aarch64
from . import amd64
from . import arm
from . import i386
from . import mips
from . import thumb

arches = {
    'arm': arm,
    'i386': i386,
    'mips': mips,
    'x86-64': amd64,
    'aarch64': aarch64
}

def syscall(value):
    """
    Given a value for a syscall number (e.g. execve == 11), return
    the *name* of the syscall.
    """
    arch = arches.get(pwndbg.arch.current, None)

    if not arch:
        return None

    prefix = '__NR_'

    for k, v in arch.__dict__.items():
        if v != value:
            continue

        if not k.startswith(prefix):
            continue

        return k[len(prefix):].lower()

    return None
