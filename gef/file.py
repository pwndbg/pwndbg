#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb
import gef.remote
import tempfile

def get(path):
    """
    Retrieves the contents of the specified file on the system
    where the current process is being debugged.

    Returns:
        A byte array, or None.
    """
    local_path = path

    if gef.remote.is_remote():
        local_path = tempfile.mktemp()
        error      = gdb.execute('remote get %s %s' % (path, local_path),
                                 to_string=True)

        if error:
            raise Exception("Could not download remote file %r:\n" \
                            "Error: %s" % (path, error))

    with open(local_path,'rb') as f:
        return f.read()


