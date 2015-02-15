#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Routines to enumerate mapped memory, and attempt to associate
address ranges with various ELF files and permissions.

The reason that we need robustness is that not every operating
system has /proc/$$/maps, which backs 'info proc mapping'.
"""
import gdb

import gef.remote
import gef.memory
import gef.types
import gef.file
import gef.proc
import gef.compat
import gef.memoize

@gef.memoize.memoize
def get():
    pages = proc_pid_maps()

    if not pages:
        pages = info_auxv()

        if pages: pages += info_sharedlibrary()
        else:     pages = info_files()

    return pages


def proc_pid_maps():
    """
    Parse the contents of /proc/$PID/maps on the server.

    Returns:
        A list of gef.memory.Page objects.
    """

    example_proc_pid_maps = """
    7f95266fa000-7f95268b5000 r-xp 00000000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    7f95268b5000-7f9526ab5000 ---p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    7f9526ab5000-7f9526ab9000 r--p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    7f9526ab9000-7f9526abb000 rw-p 001bf000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    7f9526abb000-7f9526ac0000 rw-p 00000000 00:00 0
    7f9526ac0000-7f9526ae3000 r-xp 00000000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    7f9526cbe000-7f9526cc1000 rw-p 00000000 00:00 0
    7f9526ce0000-7f9526ce2000 rw-p 00000000 00:00 0
    7f9526ce2000-7f9526ce3000 r--p 00022000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    7f9526ce3000-7f9526ce4000 rw-p 00023000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    7f9526ce4000-7f9526ce5000 rw-p 00000000 00:00 0
    7f9526ce5000-7f9526d01000 r-xp 00000000 08:01 786466                     /bin/dash
    7f9526f00000-7f9526f02000 r--p 0001b000 08:01 786466                     /bin/dash
    7f9526f02000-7f9526f03000 rw-p 0001d000 08:01 786466                     /bin/dash
    7f9526f03000-7f9526f05000 rw-p 00000000 00:00 0
    7f95279fe000-7f9527a1f000 rw-p 00000000 00:00 0                          [heap]
    7fff3c177000-7fff3c199000 rw-p 00000000 00:00 0                          [stack]
    7fff3c1e8000-7fff3c1ea000 r-xp 00000000 00:00 0                          [vdso]
    ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
    """

    locations = [
        '/proc/%s/maps' % gef.proc.pid,
        '/proc/%s/map'  % gef.proc.pid,
        '/usr/compat/linux/proc/%s/maps'  % gef.proc.pid,
    ]

    for location in locations:
        try:
            data = gef.file.get(location)
            break
        except (OSError, gdb.error):
            continue
    else:
        return []

    if gef.compat.python3:
        data = data.decode()

    pages = []
    for line in data.splitlines():
        maps, perm, offset, dev, inode_objfile = line.split(None, 4)

        try:    inode, objfile = inode_objfile.split()
        except: objfile = None

        start, stop = maps.split('-')

        start  = int(start, 16)
        stop   = int(stop, 16)
        offset = int(offset, 16)
        size   = stop-start

        flags = 0
        if 'r' in perm: flags |= 4
        if 'w' in perm: flags |= 2
        if 'x' in perm: flags |= 1

        page = gef.memory.Page(start, size, flags, offset, objfile)
        pages.append(page)

    return sorted(pages)


def info_sharedlibrary():
    """
    Parses the output of `info sharedlibrary`.

    Specifically, all we really want is any valid pointer into each library,
    and the path to the library on disk.

    With this information, we can use the ELF parser to get all of the
    page permissions for every mapped page in the ELF.

    Returns:
        A list of gef.memory.Page objects.
    """

    exmaple_info_sharedlibrary_freebsd = """
    From        To          Syms Read   Shared Object Library
    0x280fbea0  0x2810e570  Yes (*)     /libexec/ld-elf.so.1
    0x281260a0  0x281495c0  Yes (*)     /lib/libncurses.so.8
    0x28158390  0x2815dcf0  Yes (*)     /usr/local/lib/libintl.so.9
    0x28188b00  0x2828e060  Yes (*)     /lib/libc.so.7
    (*): Shared library is missing debugging information.
    """

    exmaple_info_sharedlibrary_linux = """
    From                To                  Syms Read   Shared Object Library
    0x00007ffff7ddaae0  0x00007ffff7df54e0  Yes         /lib64/ld-linux-x86-64.so.2
    0x00007ffff7bbd3d0  0x00007ffff7bc9028  Yes (*)     /lib/x86_64-linux-gnu/libtinfo.so.5
    0x00007ffff79aded0  0x00007ffff79ae9ce  Yes         /lib/x86_64-linux-gnu/libdl.so.2
    0x00007ffff76064a0  0x00007ffff774c113  Yes         /lib/x86_64-linux-gnu/libc.so.6
    (*): Shared library is missing debugging information.
    """
    pages = []
    for line in gdb.execute('info sharedlibrary', to_string=True).splitlines():
        if not line.startswith('0x'):
            continue

        tokens = line.split()
        text   = int(tokens[0], 16)
        obj    = tokens[-1]

        pages.extend(gef.elf.load(text, obj))

    return sorted(pages)

def info_files():

    example_info_files_linues = """
    Symbols from "/bin/bash".
    Unix child process:
    Using the running image of child process 5903.
    While running this, GDB does not access memory from...
    Local exec file:
    `/bin/bash', file type elf64-x86-64.
    Entry point: 0x42020b
    0x0000000000400238 - 0x0000000000400254 is .interp
    0x0000000000400254 - 0x0000000000400274 is .note.ABI-tag
    ...
    0x00000000006f06c0 - 0x00000000006f8ca8 is .data
    0x00000000006f8cc0 - 0x00000000006fe898 is .bss
    0x00007ffff7dda1c8 - 0x00007ffff7dda1ec is .note.gnu.build-id in /lib64/ld-linux-x86-64.so.2
    0x00007ffff7dda1f0 - 0x00007ffff7dda2ac is .hash in /lib64/ld-linux-x86-64.so.2
    0x00007ffff7dda2b0 - 0x00007ffff7dda38c is .gnu.hash in /lib64/ld-linux-x86-64.so.2
    """

    seen_files = set()
    pages      = []
    main_exe   = ''

    for line in gdb.execute('info files', to_string=True).splitlines():
        line = line.strip()

        # The name of the main executable
        if line.startswith('`'):
            exename, filetype = line.split(None, 1)
            main_exe = exename.strip("`,'")
            continue

        # Everything else should be addresses
        if not line.startswith('0x'):
            continue

        # start, stop, _, segment, _, filename = line.split(None,6)
        fields = line.split(None,6)
        vaddr  = int(fields[0], 16)

        if len(fields) == 5:    objfile = main_exe
        elif len(fields) == 7:  objfile = fields[6]
        else:
            print("Bad data: %r" % line)
            continue

        if objfile in seen_files:
            continue
        else:
            seen_files.add(objfile)

        pages.extend(gef.elf.load(vaddr, objfile))

    return sorted(pages)




def info_auxv(skip_exe=False):
    """
    Extracts the name of the executable from the output of the command
    "info auxv".

    Arguments:
        skip_exe(bool): Do not return any mappings that belong to the exe.

    Returns:
        A list of gef.memory.Page objects.
    """
    try:
        info_auxv = gdb.execute('info auxv', to_string=True)
    except (OSError, gdb.error):
        return []

    example_info_auxv_linux = """
    33   AT_SYSINFO_EHDR      System-supplied DSO's ELF header 0x7ffff7ffa000
    16   AT_HWCAP             Machine-dependent CPU capability hints 0xfabfbff
    6    AT_PAGESZ            System page size               4096
    17   AT_CLKTCK            Frequency of times()           100
    3    AT_PHDR              Program headers for program    0x400040
    4    AT_PHENT             Size of program header entry   56
    5    AT_PHNUM             Number of program headers      9
    7    AT_BASE              Base address of interpreter    0x7ffff7dda000
    8    AT_FLAGS             Flags                          0x0
    9    AT_ENTRY             Entry point of program         0x42020b
    11   AT_UID               Real user ID                   1000
    12   AT_EUID              Effective user ID              1000
    13   AT_GID               Real group ID                  1000
    14   AT_EGID              Effective group ID             1000
    23   AT_SECURE            Boolean, was exec setuid-like? 0
    25   AT_RANDOM            Address of 16 random bytes     0x7fffffffdb39
    31   AT_EXECFN            File name of executable        0x7fffffffefee "/bin/bash"
    15   AT_PLATFORM          String identifying platform    0x7fffffffdb49 "x86_64"
    0    AT_NULL              End of vector                  0x0
    """

    exe_name = ''
    pages    = []
    entry    = phdr = stack = vdso = None

    for line in info_auxv.splitlines():
        if 'AT_EXECFN' in line:
            exe_name = line.split()[-1].strip('"')
            stack    = int(line.split()[-2], 16)
        if 'AT_ENTRY' in line:
            entry    = int(line.split()[-1], 16)
        if 'AT_PHDR'  in line:
            phdr     = int(line.split()[-1], 16)
        if 'AT_SYSINFO_EHDR' in line:
            vdso     = int(line.split()[-1], 16)

    if not skip_exe and (entry or phdr):
        pages.extend(gef.elf.load(entry or phdr, exe_name))

    if stack:
        pages.append(find_boundaries(stack, '[stack]'))

    if vdso:
        pages.append(find_boundaries(stack, '[vdso]'))

    return sorted(pages)

def find_boundaries(addr, name=''):
    """
    Given a single address, find all contiguous pages
    which are mapped.
    """
    addr = gef.memory.page_align(int(addr))
    start = end = addr

    try:
        while True:
            gef.memory.read(start, 1)
            start -= gef.memory.PAGE_SIZE
    except gdb.MemoryError:
        pass


    try:
        while True:
            gef.memory.read(end, 1)
            end += gef.memory.PAGE_SIZE
    except gdb.MemoryError:
        pass

    return gef.memory.Page(start, end-start, 4, 0, name)
