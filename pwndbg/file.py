#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Retrieve files from the debuggee's filesystem.  Useful when
debugging a remote process over SSH or similar, where e.g.
/proc/FOO/maps is needed from the remote system.
"""
import os
import tempfile

import gdb
import pwndbg.qemu
import pwndbg.remote


def get(path, recurse=1):
    """
    Retrieves the contents of the specified file on the system
    where the current process is being debugged.

    Returns:
        A byte array, or None.
    """
    local_path = path

    if pwndbg.qemu.root() and recurse:
        return get(os.path.join(pwndbg.qemu.root, path), 0)
    elif pwndbg.remote.is_remote() and not pwndbg.qemu.is_qemu():
        local_path = tempfile.mktemp()
        error      = None
        try:
            error = gdb.execute('remote get %s %s' % (path, local_path),
                                 to_string=True)
        except gdb.error as e:
            error = e

        if error:
            raise OSError("Could not download remote file %r:\n" \
                            "Error: %s" % (path, error))

    try:
        with open(local_path,'rb') as f:
            return f.read()
    except:
        return b''
