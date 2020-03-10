#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Retrieve files from the debuggee's filesystem.  Useful when
debugging a remote process over SSH or similar, where e.g.
/proc/FOO/maps is needed from the remote system.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import binascii
import os
import tempfile

import gdb

import pwndbg.qemu
import pwndbg.remote
import pwndbg.symbol


def get_file(path):
    """
    Downloads the specified file from the system where the current process is
    being debugged.

    Returns:
        The local path to the file
    """
    local_path = path

    if pwndbg.qemu.root():
        return os.path.join(pwndbg.qemu.binfmt_root, path)
    elif pwndbg.remote.is_remote() and not pwndbg.qemu.is_qemu():
        local_path = tempfile.mktemp(dir=pwndbg.symbol.remote_files_dir)
        error      = None
        try:
            error = gdb.execute('remote get "%s" "%s"' % (path, local_path),
                                 to_string=True)
        except gdb.error as e:
            error = e

        if error:
            raise OSError("Could not download remote file %r:\n" \
                            "Error: %s" % (path, error))

    return local_path

def get(path):
    """
    Retrieves the contents of the specified file on the system
    where the current process is being debugged.

    Returns:
        A byte array, or None.
    """
    local_path = get_file(path)

    try:
        with open(local_path,'rb') as f:
            return f.read()
    except:
        return b''

def readlink(path):
    """readlink(path) -> str

    Read the link specified by 'path' on the system being debugged.

    Handles local, qemu-usermode, and remote debugging cases.
    """
    is_qemu = pwndbg.qemu.is_qemu_usermode()

    if is_qemu:
        if not os.path.exists(path):
            path = os.path.join(pwndbg.qemu.root(), path)

    if is_qemu or not pwndbg.remote.is_remote():
        try:
            return os.readlink(path)
        except Exception:
            return ''

    #
    # Hurray unexposed packets!
    #
    # The 'vFile:readlink:' packet does exactly what it sounds like,
    # but there is no API exposed to do this and there is also no
    # command exposed... so we have to send the packet manually.
    #
    cmd = 'maintenance packet vFile:readlink:%s'

    # The path must be uppercase hex-encoded and NULL-terminated.
    path += '\x00'
    path = binascii.hexlify(path.encode())
    path = path.upper()
    path = path.decode()

    result = gdb.execute(cmd % path, from_tty=False, to_string=True)

    """
    sending: "vFile:readlink:2F70726F632F3130303839302F66642F3000"
    received: "Fc;pipe:[98420]"

    sending: "vFile:readlink:2F70726F632F3130303839302F66642F333300"
    received: "F-1,2"
    """

    _, data = result.split('\n', 1)

    # Sanity check
    expected = 'received: "F'
    if not data.startswith(expected):
        return ''

    # Negative values are errors
    data = data[len(expected):]
    if data[0] == '-':
        return ''

    # If non-negative, there will be a hex-encoded length followed
    # by a semicolon.
    n, data = data.split(';', 1)

    n = int(n, 16)
    if n < 0:
        return ''

    # The result is quoted by GDB, strip the quote and newline.
    # I have no idea how well it handles other crazy stuff.
    ending = '"\n'
    data = data[:-len(ending)]

    return data
