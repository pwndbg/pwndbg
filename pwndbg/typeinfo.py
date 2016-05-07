#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Common types, and routines for manually loading types from file
via GCC.
"""
from __future__ import print_function
import glob
import os
import subprocess
import sys
import tempfile

import gdb
import pwndbg.events
import pwndbg.gcc
import pwndbg.memoize

module = sys.modules[__name__]

def is_pointer(value):
    type = value

    if isinstance(value, gdb.Value):
        type = value.type

    type = type.strip_typedefs()
    return type.code == gdb.TYPE_CODE_PTR

@pwndbg.events.start
@pwndbg.events.stop
def update():
    module.char   = gdb.lookup_type('char')
    module.ulong  = gdb.lookup_type('unsigned long')
    module.long   = gdb.lookup_type('long')
    module.uchar  = gdb.lookup_type('unsigned char')
    module.ushort = gdb.lookup_type('unsigned short')
    module.uint   = gdb.lookup_type('unsigned int')
    module.void   = gdb.lookup_type('void')
    module.uint8  = gdb.lookup_type('unsigned char')
    module.uint16 = gdb.lookup_type('unsigned short')
    module.uint32 = gdb.lookup_type('unsigned int')
    module.uint64 = gdb.lookup_type('unsigned long long')

    module.int8   = gdb.lookup_type('char')
    module.int16  = gdb.lookup_type('short')
    module.int32  = gdb.lookup_type('int')
    module.int64  = gdb.lookup_type('long long')

    module.pvoid  = void.pointer()
    module.ppvoid = pvoid.pointer()
    module.pchar  = char.pointer()

    module.ptrsize = pvoid.sizeof

    if pvoid.sizeof == 4: module.ptrdiff = uint32
    if pvoid.sizeof == 8: module.ptrdiff = uint64

    module.null = gdb.Value(0).cast(void)

# Call it once so we load all of the types
update()

tempdir = tempfile.gettempdir() + '/pwndbg'
if not os.path.exists(tempdir):
    os.mkdir(tempdir)

# Trial and error until things work
blacklist = ['regexp.h', 'xf86drm.h', 'libxl_json.h', 'xf86drmMode.h',
'caca0.h', 'xenguest.h', '_libxl_types_json.h', 'term_entry.h', 'slcurses.h',
'pcreposix.h', 'sudo_plugin.h', 'tic.h', 'sys/elf.h', 'sys/vm86.h',
'xenctrlosdep.h', 'xenctrl.h', 'cursesf.h', 'cursesm.h', 'gdbm.h', 'dbm.h',
'gcrypt-module.h', 'term.h', 'gmpxx.h', 'pcap/namedb.h', 'pcap-namedb.h',
'evr.h', 'mpc.h', 'fdt.h', 'mpfr.h', 'evrpc.h', 'png.h', 'zlib.h', 'pngconf.h',
'libelfsh.h', 'libmjollnir.h', 'hwloc.h', 'ares.h', 'revm.h', 'ares_rules.h',
'libunwind-ptrace.h', 'libui.h', 'librevm-color.h', 'libedfmt.h','revm-objects.h',
'libetrace.h', 'revm-io.h','libasm-mips.h','libstderesi.h','libasm.h','libaspect.h',
'libunwind.h','libmjollnir-objects.h','libunwind-coredump.h','libunwind-dynamic.h']

def load(name):
    try:
        return gdb.lookup_type(name)
    except gdb.error:
        pass

    # s, _ = gdb.lookup_symbol(name)

    # Try to find an architecture-specific include path
    arch = pwndbg.arch.current.split(':')[0]

    include_dir = glob.glob('/usr/%s*/include' % arch)

    if include_dir:
        include_dir = include_dir[0]
    else:
        include_dir = '/usr/include'

    source = '#include <fstream>\n'

    for subdir in ['', 'sys', 'netinet']:
        dirname = os.path.join(include_dir, subdir)
        for path in glob.glob(os.path.join(dirname, '*.h')):
            if any(b in path for b in blacklist):
              continue
            print(path)
            source += '#include "%s"\n' % path


    source += '''
{name} foo;
'''.format(**locals())

    filename = '%s/%s_%s' % (tempdir, arch, '-'.join(name.split()))

    if not os.path.exists(filename + '.o'):
        with open(filename + '.cc', 'w+') as f:
            f.write(source)
            f.flush()

        gcc     = pwndbg.gcc.which()
        gcc    += ['-w','-c','-g',filename + '.cc','-o',filename + '.o']
        subprocess.check_output(' '.join(gcc), shell=True)

    with pwndbg.events.Pause():
        gdb.execute('add-symbol-file %s.o 0' % filename, from_tty=False, to_string=True)

    return gdb.lookup_type(name)
