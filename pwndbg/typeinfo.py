#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Common types, and routines for manually loading types from file
via GCC.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import glob
import os
import re
import subprocess
import sys
import tempfile

import gdb

import pwndbg.events
import pwndbg.gcc
import pwndbg.memoize
import pwndbg.storage

module = sys.modules[__name__]


def is_pointer(value):
    type = value

    if isinstance(value, gdb.Value):
        type = value.type

    type = type.strip_typedefs()
    return type.code == gdb.TYPE_CODE_PTR


def lookup_types(*types):
    for type_str in types:
        try:
            return gdb.lookup_type(type_str)
        except Exception as e:
            exc = e
    raise exc


@pwndbg.events.start
@pwndbg.events.stop
def update():

    module.char   = gdb.lookup_type('char')
    module.ulong  = lookup_types('unsigned long', 'uint')
    module.long   = lookup_types('long', 'int')
    module.uchar  = lookup_types('unsigned char', 'ubyte')
    module.ushort = lookup_types('unsigned short', 'ushort')
    module.uint   = lookup_types('unsigned int', 'uint')
    module.void   = gdb.lookup_type('void')
    module.uint8  = module.uchar
    module.uint16 = module.ushort
    module.uint32 = module.uint
    module.uint64 = lookup_types('unsigned long long', 'ulong')

    module.int8   = gdb.lookup_type('char')
    module.int16  = gdb.lookup_type('short')
    module.int32  = gdb.lookup_type('int')
    module.int64  = lookup_types('long long', 'long')

    module.ssize_t = module.long
    module.size_t = module.ulong

    module.pvoid  = void.pointer()
    module.ppvoid = pvoid.pointer()
    module.pchar  = char.pointer()

    module.ptrsize = pvoid.sizeof

    if pvoid.sizeof == 4: module.ptrdiff = uint32
    if pvoid.sizeof == 8: module.ptrdiff = uint64

    module.null = gdb.Value(0).cast(void)

# Call it once so we load all of the types
update()

tempdir = os.path.join(tempfile.gettempdir(), 'pwndbg')
if not os.path.exists(tempdir):
    os.mkdir(tempdir)

@pwndbg.storage.file_cache_with_signature_for_text('{0}.skeleton.h')
def find_compilable_headers(arch, headers):
    """Find maximum fixed point of compilable header files by alternating compiling and removing bad headers."""
    print('typeinfo: %s' % find_compilable_headers.__doc__)
    filename = '{}/{}.skeleton.cc'.format(tempdir, arch)
    headers = set(headers)
    tries = 0

    while True:
        if tries % 10 == 0:
            print('typeinfo: Trial %d, compiling with %d header files' % (tries, len(headers)))
        body = ''.join('#include "%s"\n' % i for i in headers)
        with open(filename, 'w') as f:
            f.write(body)
        try:
            subprocess.check_output(pwndbg.gcc.which() + ['-fsyntax-only', '-w', filename], stderr=subprocess.STDOUT)
            return body
        except subprocess.CalledProcessError as e:
            found = False
            for header in re.findall(r'/usr/\S+\.h', e.stdout.decode('utf-8')):
                try:
                    headers.remove(header)
                    found = True
                except KeyError:
                    pass
            assert found, 'Failed to find a bad header file.'
            tries += 1

def load(name, include_system_headers=True, extra_headers=()):
    """Load symbol by name from headers in standard system include directory"""
    try:
        return gdb.lookup_type(name)
    except gdb.error:
        pass

    # s, _ = gdb.lookup_symbol(name)

    # Try to find an architecture-specific include path
    arch = pwndbg.arch.current.split(':')[0]
    include_dir = None
    for i in glob.glob('/usr/%s*/include' % arch):
        if 'mingw' not in i:
            include_dir = i
    if not include_dir:
        include_dir = '/usr/include'
    headers = []
    for subdir in ['', 'sys', 'netinet']:
        dirname = os.path.join(include_dir, subdir)
        headers.extend(glob.glob(os.path.join(dirname, '*.h')))
    headers = set(headers)
    skeleton = find_compilable_headers(arch, headers, signature=sum(len(i) for i in headers))

    filename = '%s/%s_%s.cc' % (tempdir, arch, '-'.join(name.split()))
    with open(filename, 'w') as f:
        if include_system_headers:
            f.write(skeleton)
        if extra_headers:
            f.write(''.join('#include "%s"\n' % i for i in extra_headers))
        f.write('''
{name} foo;
'''.format(**locals()))

    compile(filename)

    return gdb.lookup_type(name)

def compile(filename=None, address=0):
    """Compile and extract symbols from specified file"""
    if filename is None:
        print("Specify a filename to compile.")
        return

    objectname = os.path.splitext(filename)[0] + ".o"

    if not os.path.exists(objectname):
        subprocess.check_output(pwndbg.gcc.which() + ['-w', '-c', '-g', filename, '-o', objectname])

    add_symbol_file(objectname, address)

def add_symbol_file(filename=None, address=0):
    """Read additional symbol table information from the object file filename"""
    if filename is None:
        print("Specify a symbol file to add.")
        return

    with pwndbg.events.Pause():
        gdb.execute('add-symbol-file %s %s' % (filename, address), from_tty=False, to_string=True)
