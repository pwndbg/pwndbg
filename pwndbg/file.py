#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Retrieve files from the debuggee's filesystem.  Useful when
debugging a remote process over SSH or similar, where e.g.
/proc/FOO/maps is needed from the remote system.
"""
import tempfile

import gdb
import pwndbg.remote


def get(path):
    """
    Retrieves the contents of the specified file on the system
    where the current process is being debugged.

    Returns:
        A byte array, or None.
    """
    local_path = path

    if pwndbg.remote.is_remote():
        local_path = tempfile.mktemp()
        error      = gdb.execute('remote get %s %s' % (path, local_path),
                                 to_string=True)

        if error:
            raise OSError("Could not download remote file %r:\n" \
                            "Error: %s" % (path, error))

    with open(local_path,'rb') as f:
        return f.read()
