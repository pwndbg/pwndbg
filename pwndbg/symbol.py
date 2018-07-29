#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Looking up addresses for function names / symbols, and
vice-versa.

Uses IDA when available if there isn't sufficient symbol
information available.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import re
import tempfile

import elftools.common.exceptions
import elftools.elf.constants
import elftools.elf.elffile
import elftools.elf.segments
import gdb
import six

import pwndbg.arch
import pwndbg.elf
import pwndbg.events
import pwndbg.file
import pwndbg.ida
import pwndbg.memoize
import pwndbg.memory
import pwndbg.qemu
import pwndbg.remote
import pwndbg.stack
import pwndbg.vmmap


def get_directory():
    """
    Retrieve the debug file directory path.

    The debug file directory path ('show debug-file-directory') is a comma-
    separated list of directories which GDB will look in to find the binaries
    currently loaded.
    """
    result = gdb.execute('show debug-file-directory', to_string=True, from_tty=False)
    expr   = r'The directory where separate debug symbols are searched for is "(.*)".\n'

    match = re.search(expr, result)

    if match:
        return match.group(1)
    return ''

def set_directory(d):
    gdb.execute('set debug-file-directory %s' % d, to_string=True, from_tty=False)

def add_directory(d):
    current = get_directory()
    if current:
        set_directory('%s:%s' % (current, d))
    else:
        set_directory(d)

remote_files = {}
remote_files_dir = None

@pwndbg.events.exit
def reset_remote_files():
    global remote_files
    global remote_files_dir
    remote_files = {}
    remote_files_dir = tempfile.mkdtemp()

@pwndbg.events.new_objfile
def autofetch():
    """
    """
    global remote_files_dir
    if not pwndbg.remote.is_remote():
        return

    if pwndbg.qemu.is_qemu_usermode():
        return

    if pwndbg.android.is_android():
        return

    if not remote_files_dir:
        remote_files_dir = tempfile.mkdtemp()
        add_directory(remote_files_dir)

    searchpath = get_directory()

    for mapping in pwndbg.vmmap.get():
        objfile = mapping.objfile

        # Don't attempt to download things like '[stack]' and '[heap]'
        if not objfile.startswith('/'):
            continue

        # Don't re-download things that we have already downloaded
        if not objfile or objfile in remote_files:
            continue

        msg = "Downloading %r from the remote server" % objfile
        print(msg, end='')

        try:
            data = pwndbg.file.get(objfile)
            print('\r' + msg + ': OK')
        except OSError:
            # The file could not be downloaded :(
            print('\r' + msg + ': Failed')
            return

        filename = os.path.basename(objfile)
        local_path = os.path.join(remote_files_dir, filename)

        with open(local_path, 'wb+') as f:
            f.write(data)

        remote_files[objfile] = local_path

        base = None
        for mapping in pwndbg.vmmap.get():
            if mapping.objfile != objfile:
                continue

            if base is None or mapping.vaddr < base.vaddr:
                base = mapping

        if not base:
            continue

        base = base.vaddr

        try:
            elf = elftools.elf.elffile.ELFFile(open(local_path, 'rb'))
        except elftools.common.exceptions.ELFError:
            continue

        gdb_command = ['add-symbol-file', local_path, hex(int(base))]
        for section in elf.iter_sections():
            name = section.name #.decode('latin-1')
            section = section.header
            if not section.sh_flags & elftools.elf.constants.SH_FLAGS.SHF_ALLOC:
                continue
            gdb_command += ['-s', name, hex(int(base + section.sh_addr))]

        print(' '.join(gdb_command))
        # gdb.execute(' '.join(gdb_command), from_tty=False, to_string=True)

@pwndbg.memoize.reset_on_objfile
def get(address, gdb_only=False):
    """
    Retrieve the textual name for a symbol
    """
    # Fast path
    if address < pwndbg.memory.MMAP_MIN_ADDR or address >= ((1 << 64)-1):
        return ''

    # Don't look up stack addresses
    if pwndbg.stack.find(address):
        return ''

    # This sucks, but there's not a GDB API for this.
    result = gdb.execute('info symbol %#x' % int(address), to_string=True, from_tty=False)

    if not gdb_only and result.startswith('No symbol'):
        address = int(address)
        exe     = pwndbg.elf.exe()
        if exe:
            exe_map = pwndbg.vmmap.find(exe.address)
            if exe_map and address in exe_map:
                res =  pwndbg.ida.Name(address) or pwndbg.ida.GetFuncOffset(address)
                return res or ''

    # Expected format looks like this:
    # main in section .text of /bin/bash
    # main + 3 in section .text of /bin/bash
    # system + 1 in section .text of /lib/x86_64-linux-gnu/libc.so.6
    # No symbol matches system-1.
    a, b, c, _ = result.split(None, 3)


    if b == '+':
        return "%s+%s" % (a, c)
    if b == 'in':
        return a

    return ''

@pwndbg.memoize.reset_on_objfile
def address(symbol):
    if isinstance(symbol, six.integer_types):
        return symbol

    try:
        return int(symbol, 0)
    except:
        pass

    try:
        symbol_obj = gdb.lookup_symbol(symbol)[0]
        if symbol_obj:
            return int(symbol_obj.value().address)
    except Exception:
        pass

    try:
        result = gdb.execute('info address %s' % symbol, to_string=True, from_tty=False)
        address = re.search('0x[0-9a-fA-F]+', result).group()
        return int(address, 0)
    except gdb.error:
        return None

    try:
        address = pwndbg.ida.LocByName(symbol)
        if address:
            return address
    except Exception:
        pass

@pwndbg.events.stop
@pwndbg.memoize.reset_on_start
def add_main_exe_to_symbols():
    if not pwndbg.remote.is_remote():
        return

    if pwndbg.android.is_android():
        return

    exe  = pwndbg.elf.exe()

    if not exe:
        return

    addr = exe.address

    if not addr:
        return

    addr = int(addr)

    mmap = pwndbg.vmmap.find(addr)
    if not mmap:
        return

    path = mmap.objfile
    if path and (pwndbg.arch.endian == pwndbg.arch.native_endian):
        try:
            gdb.execute('add-symbol-file %s %#x' % (path, addr), from_tty=False, to_string=True)
        except gdb.error:
            pass

if '/usr/lib/debug' not in get_directory():
    set_directory(get_directory() + ':/usr/lib/debug')
