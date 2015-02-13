#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Routines to enumerate mapped memory, and attempt to associate
address ranges with various ELF files and permissions.
"""
import gdb

import gef.remote
import gef.memory
import gef.types
import gef.file
import gef.proc
import gef.compat

def parse_proc_pid_maps_line(line):
    print(repr(line))

    maps, perm, offset, dev, inode_objfile = line.split(None, 4)

    try:
        inode, objfile = inode_objfile.split()
    except:
        objfile = ''

    start, stop = maps.split('-')

    start  = int(start, 16)
    stop   = int(stop, 16)
    offset = int(offset, 16)
    size   = stop-start

    flags = 0
    if 'r' in perm: flags |= 4
    if 'w' in perm: flags |= 2
    if 'x' in perm: flags |= 1

    page = gef.memory.Page(start, size, flags, offset)
    page.objfile = objfile
    return page

def get_proc_pid_maps():
    """
    Parse the contents of /proc/$PID/maps on the server.

    Returns:
        A list of gef.memory.Page objects.
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
        except FileNotFoundError:
            continue
    else:
        print("Could not read any /proc/pid/maps files")
        return []

    if gef.compat.python3:
        data = data.decode()

    pages = []
    for line in data.splitlines():
        pages.append(parse_proc_pid_maps_line(line))
    pages.sort()
    return pages

def get_maps_from_sharedlibraries():
    """
    Okay, so some CTF organizer decided to `chmod o-x /proc` or we're
    on FreeBSD locally without procfs mounted.

    We can still do `info sharedlibrary` to get a pointer into every
    dynamically-loaded library.  We can also use `info auxv` and
    `info files` to find the path to the main executable on disk,
    as well as its entry point.
    """



def parse_info_sharedlibrary():
    """
    Parses a single line from `info sharedlibrary`.

    Specifically, all we really want is any valid pointer into the library,
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
    all_pages = []
    for line in gdb.execute('info sharedlibrary', to_string=True).splitlines():
        print(line)
        if not line.startswith('0x'):
            continue

        tokens = line.split()
        text   = int(tokens[0], 16)
        obj    = tokens[-1]

        pages = gef.elf.load(text)

        for page in pages:
            page.objfile = obj

        all_pages.extend(pages)

    all_pages.sort()
    return all_pages

def info_files():

    seen_files = []
    all_pages  = []

    main_exe

    for line in gdb.execute('info files', to_string=True).splitlines():



def extract_exe_maps_from_auxv():
    """
    Extracts the name of the executable from the output of the command
    "info auxv".

    Returns:
        A list of gef.memory.Page objects.
    """
    info_auxv        = gdb.execute('info auxv', to_string=True)

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

    exe_name = entry = None

    for line in info_auxv.splitlines():
        if 'AT_EXECFN' in line:
            exe_name = line.split()[-1].strip('"')
        if 'AT_ENTRY' in line:
            entry    = int(line.split()[-1], 16)

    if None in (exe_name, entry):
        return []

    pages = gef.elf.load(entry)

    for page in pages:
        page.objfile = exe_name

    return pages

def extract_exe_entry_from_auxv(auxv):
    pass

def extract_exe_name_from_files(files):
    pass

def extract_exe_entry_from_files(files):
    pass

example_linux_proc_pid_maps = """
00400000-004ef000 r-xp 00000000 08:01 786437                             /bin/bash
006ef000-006f0000 r--p 000ef000 08:01 786437                             /bin/bash
006f0000-006f9000 rw-p 000f0000 08:01 786437                             /bin/bash
006f9000-006ff000 rw-p 00000000 00:00 0                                  [heap]
7ffff75e7000-7ffff77a2000 r-xp 00000000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
7ffff77a2000-7ffff79a2000 ---p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
7ffff79a2000-7ffff79a6000 r--p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
7ffff79a6000-7ffff79a8000 rw-p 001bf000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
7ffff79a8000-7ffff79ad000 rw-p 00000000 00:00 0
7ffff79ad000-7ffff79b0000 r-xp 00000000 08:01 418446                     /lib/x86_64-linux-gnu/libdl-2.19.so
7ffff79b0000-7ffff7baf000 ---p 00003000 08:01 418446                     /lib/x86_64-linux-gnu/libdl-2.19.so
7ffff7baf000-7ffff7bb0000 r--p 00002000 08:01 418446                     /lib/x86_64-linux-gnu/libdl-2.19.so
7ffff7bb0000-7ffff7bb1000 rw-p 00003000 08:01 418446                     /lib/x86_64-linux-gnu/libdl-2.19.so
7ffff7bb1000-7ffff7bd6000 r-xp 00000000 08:01 397852                     /lib/x86_64-linux-gnu/libtinfo.so.5.9
7ffff7bd6000-7ffff7dd5000 ---p 00025000 08:01 397852                     /lib/x86_64-linux-gnu/libtinfo.so.5.9
7ffff7dd5000-7ffff7dd9000 r--p 00024000 08:01 397852                     /lib/x86_64-linux-gnu/libtinfo.so.5.9
7ffff7dd9000-7ffff7dda000 rw-p 00028000 08:01 397852                     /lib/x86_64-linux-gnu/libtinfo.so.5.9
7ffff7dda000-7ffff7dfd000 r-xp 00000000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
7ffff7fd6000-7ffff7fd9000 rw-p 00000000 00:00 0
7ffff7ff8000-7ffff7ffa000 rw-p 00000000 00:00 0
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00022000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
7ffff7ffd000-7ffff7ffe000 rw-p 00023000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0
7ffffffdd000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
"""

example_freebsd_linux_compat_maps = """
08048000-080fb000 r-xp 000b7000 00:00 805983     /usr/local/bin/bash
080fb000-080ff000 rw-p 000b7000 00:00 805983     /usr/local/bin/bash
080ff000-08103000 rw-p 00004000 00:00 0
280fb000-28111000 r-xp 00018000 00:00 2247170     /libexec/ld-elf.so.1
28111000-28119000 rw-p 00008000 00:00 0
2811b000-28154000 r-xp 0003c000 00:00 2407719     /lib/libncurses.so.8
28154000-28157000 rw-p 0003c000 00:00 2407719     /lib/libncurses.so.8
28157000-2815f000 r-xp 0000b000 00:00 804759     /usr/local/lib/libintl.so.9
2815f000-28160000 rw-p 0000b000 00:00 804759     /usr/local/lib/libintl.so.9
28160000-2829e000 r-xp 00154000 00:00 2407726     /lib/libc.so.7
2829e000-282a5000 rw-p 00154000 00:00 2407726     /lib/libc.so.7
282a5000-282df000 rw-p 0003a000 00:00 0
bfbdf000-bfbff000 rwxp 00020000 00:00 0
bfbff000-bfc00000 r-xp 00001000 00:00 0
"""


def parse_info_proc_mapping_line(line):
    if line.startswith("process"):
        return None
    if "Mapped address spaces" in line:
        return None
    if not line.strip():
        return None

    start, end, size, offset, obj = line.split(None, 5)

    start = int(start, 16)
    stop  = int(stop, 16)

    return Section(obj, start, stop, READ)


example_info_proc_mapping = """
process 57445
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x4ef000    0xef000        0x0 /bin/bash
            0x6ef000           0x6f0000     0x1000    0xef000 /bin/bash
            0x6f0000           0x6f9000     0x9000    0xf0000 /bin/bash
            0x6f9000           0x6ff000     0x6000        0x0 [heap]
      0x7ffff75e7000     0x7ffff77a2000   0x1bb000        0x0 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff77a2000     0x7ffff79a2000   0x200000   0x1bb000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff79a2000     0x7ffff79a6000     0x4000   0x1bb000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff79a6000     0x7ffff79a8000     0x2000   0x1bf000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff79a8000     0x7ffff79ad000     0x5000        0x0
      0x7ffff79ad000     0x7ffff79b0000     0x3000        0x0 /lib/x86_64-linux-gnu/libdl-2.19.so
      0x7ffff79b0000     0x7ffff7baf000   0x1ff000     0x3000 /lib/x86_64-linux-gnu/libdl-2.19.so
      0x7ffff7baf000     0x7ffff7bb0000     0x1000     0x2000 /lib/x86_64-linux-gnu/libdl-2.19.so
      0x7ffff7bb0000     0x7ffff7bb1000     0x1000     0x3000 /lib/x86_64-linux-gnu/libdl-2.19.so
      0x7ffff7bb1000     0x7ffff7bd6000    0x25000        0x0 /lib/x86_64-linux-gnu/libtinfo.so.5.9
      0x7ffff7bd6000     0x7ffff7dd5000   0x1ff000    0x25000 /lib/x86_64-linux-gnu/libtinfo.so.5.9
      0x7ffff7dd5000     0x7ffff7dd9000     0x4000    0x24000 /lib/x86_64-linux-gnu/libtinfo.so.5.9
      0x7ffff7dd9000     0x7ffff7dda000     0x1000    0x28000 /lib/x86_64-linux-gnu/libtinfo.so.5.9
      0x7ffff7dda000     0x7ffff7dfd000    0x23000        0x0 /lib/x86_64-linux-gnu/ld-2.19.so
      0x7ffff7fd6000     0x7ffff7fd9000     0x3000        0x0
      0x7ffff7ff8000     0x7ffff7ffa000     0x2000        0x0
      0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0 [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x22000 /lib/x86_64-linux-gnu/ld-2.19.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x23000 /lib/x86_64-linux-gnu/ld-2.19.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0
      0x7ffffffdd000     0x7ffffffff000    0x22000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
"""


def parse_info_maintenance_sections(all_lines):
    sections = []
    filename = None
    section  = None
    for line in all_lines.splitlines():
        if 'Exec file' in line:
            continue
        if 'file type' in line:
            filename, _ = line.split(None, 1)
            filename    = filename[1:-2] # strip "`" and "',"
            continue

        num, addresses, at, offset, name, flags = line.split(None, 5)

        start, stop = addresses.split('->')
        start       = int(start, 16)
        stop        = int(stop,  16)
        permissions = 0

        for flag in flags.split():
            if flag == 'READONLY':
                permissions |= READ
                permissions &= ~WRITE
            if flag == 'CODE':
                permissions |= (READ|EXEC)
            if flag == 'DATA':
                permissions |= (READ|WRITE)

        print(hex(start), hex(stop), permissions)

        # Round start and stop to nearest page
        start = round_down(start, 0x1000)
        stop  = round_up(stop, 0x1000)

        # First section
        if section is None:
            section = Section(filename, start, stop, permissions)

        # Does it seem that this section is a continuation of the last one?
        # Update it.
        elif section.start <= start <= section.stop and section.permissions == permissions:
            section.start = min(section.start, start)
            section.stop  = max(section.stop, stop)

        # We've moved on to a new section.
        else:
            sections.append(section)
            section = Section(filename, start, stop, permissions)

    return sections



example_freebsd_info_maintenance_sections = """
Exec file:
    `/usr/local/bin/bash', file type elf32-i386-freebsd.
 [0]     0x8048134->0x8048149 at 0x00000134: .interp ALLOC LOAD READONLY DATA HAS_CONTENTS
 [1]     0x804814c->0x804817c at 0x0000014c: .note.tag ALLOC LOAD READONLY DATA HAS_CONTENTS
 [2]     0x804817c->0x8048814 at 0x0000017c: .hash ALLOC LOAD READONLY DATA HAS_CONTENTS
 [3]     0x8048814->0x80488cc at 0x00000814: .gnu.hash ALLOC LOAD READONLY DATA HAS_CONTENTS
 [4]     0x80488cc->0x80496bc at 0x000008cc: .dynsym ALLOC LOAD READONLY DATA HAS_CONTENTS
 [5]     0x80496bc->0x8049e04 at 0x000016bc: .dynstr ALLOC LOAD READONLY DATA HAS_CONTENTS
 [6]     0x8049e04->0x8049fc2 at 0x00001e04: .gnu.version ALLOC LOAD READONLY DATA HAS_CONTENTS
 [7]     0x8049fc4->0x804a004 at 0x00001fc4: .gnu.version_r ALLOC LOAD READONLY DATA HAS_CONTENTS
 [8]     0x804a004->0x804a074 at 0x00002004: .rel.dyn ALLOC LOAD READONLY DATA HAS_CONTENTS
 [9]     0x804a074->0x804a6a4 at 0x00002074: .rel.plt ALLOC LOAD READONLY DATA HAS_CONTENTS
 [10]     0x804a6a4->0x804a6b5 at 0x000026a4: .init ALLOC LOAD READONLY CODE HAS_CONTENTS
 [11]     0x804a6b8->0x804b328 at 0x000026b8: .plt ALLOC LOAD READONLY CODE HAS_CONTENTS
 [12]     0x804b330->0x80e1610 at 0x00003330: .text ALLOC LOAD READONLY CODE HAS_CONTENTS
 [13]     0x80e1610->0x80e161c at 0x00099610: .fini ALLOC LOAD READONLY CODE HAS_CONTENTS
 [14]     0x80e1620->0x80fa6dd at 0x00099620: .rodata ALLOC LOAD READONLY DATA HAS_CONTENTS
 [15]     0x80fa6e0->0x80fa6f4 at 0x000b26e0: .eh_frame_hdr ALLOC LOAD READONLY DATA HAS_CONTENTS
 [16]     0x80fa6f4->0x80fa72c at 0x000b26f4: .eh_frame ALLOC LOAD READONLY DATA HAS_CONTENTS
 [17]     0x80fb72c->0x80fb734 at 0x000b272c: .ctors ALLOC LOAD DATA HAS_CONTENTS
 [18]     0x80fb734->0x80fb73c at 0x000b2734: .dtors ALLOC LOAD DATA HAS_CONTENTS
 [19]     0x80fb73c->0x80fb740 at 0x000b273c: .jcr ALLOC LOAD DATA HAS_CONTENTS
 [20]     0x80fb740->0x80fb820 at 0x000b2740: .dynamic ALLOC LOAD DATA HAS_CONTENTS
 [21]     0x80fb820->0x80fb830 at 0x000b2820: .got ALLOC LOAD DATA HAS_CONTENTS
 [22]     0x80fb830->0x80fbb54 at 0x000b2830: .got.plt ALLOC LOAD DATA HAS_CONTENTS
 [23]     0x80fbb54->0x80ff8a0 at 0x000b2b54: .data ALLOC LOAD DATA HAS_CONTENTS
 [24]     0x80ff8a0->0x8102b90 at 0x000b68a0: .bss ALLOC
 [25]     0x0000->0x01fd at 0x000b68a0: .comment READONLY HAS_CONTENTS
"""

example_linux_maintenance_info_sections = """
Exec file:
    `/bin/bash', file type elf64-x86-64.
 [0]     0x00400238->0x00400254 at 0x00000238: .interp ALLOC LOAD READONLY DATA HAS_CONTENTS
 [1]     0x00400254->0x00400274 at 0x00000254: .note.ABI-tag ALLOC LOAD READONLY DATA HAS_CONTENTS
 [2]     0x00400274->0x00400298 at 0x00000274: .note.gnu.build-id ALLOC LOAD READONLY DATA HAS_CONTENTS
 [3]     0x00400298->0x00404b28 at 0x00000298: .gnu.hash ALLOC LOAD READONLY DATA HAS_CONTENTS
 [4]     0x00404b28->0x004121d8 at 0x00004b28: .dynsym ALLOC LOAD READONLY DATA HAS_CONTENTS
 [5]     0x004121d8->0x0041ade0 at 0x000121d8: .dynstr ALLOC LOAD READONLY DATA HAS_CONTENTS
 [6]     0x0041ade0->0x0041bfc4 at 0x0001ade0: .gnu.version ALLOC LOAD READONLY DATA HAS_CONTENTS
 [7]     0x0041bfc8->0x0041c078 at 0x0001bfc8: .gnu.version_r ALLOC LOAD READONLY DATA HAS_CONTENTS
 [8]     0x0041c078->0x0041c138 at 0x0001c078: .rela.dyn ALLOC LOAD READONLY DATA HAS_CONTENTS
 [9]     0x0041c138->0x0041d530 at 0x0001c138: .rela.plt ALLOC LOAD READONLY DATA HAS_CONTENTS
 [10]     0x0041d530->0x0041d54a at 0x0001d530: .init ALLOC LOAD READONLY CODE HAS_CONTENTS
 [11]     0x0041d550->0x0041e2b0 at 0x0001d550: .plt ALLOC LOAD READONLY CODE HAS_CONTENTS
 [12]     0x0041e2b0->0x004b52c2 at 0x0001e2b0: .text ALLOC LOAD READONLY CODE HAS_CONTENTS
 [13]     0x004b52c4->0x004b52cd at 0x000b52c4: .fini ALLOC LOAD READONLY CODE HAS_CONTENTS
 [14]     0x004b52e0->0x004d3cb0 at 0x000b52e0: .rodata ALLOC LOAD READONLY DATA HAS_CONTENTS
 [15]     0x004d3cb0->0x004d7cbc at 0x000d3cb0: .eh_frame_hdr ALLOC LOAD READONLY DATA HAS_CONTENTS
 [16]     0x004d7cc0->0x004eefdc at 0x000d7cc0: .eh_frame ALLOC LOAD READONLY DATA HAS_CONTENTS
 [17]     0x006efdf0->0x006efdf8 at 0x000efdf0: .init_array ALLOC LOAD DATA HAS_CONTENTS
 [18]     0x006efdf8->0x006efe00 at 0x000efdf8: .fini_array ALLOC LOAD DATA HAS_CONTENTS
 [19]     0x006efe00->0x006efe08 at 0x000efe00: .jcr ALLOC LOAD DATA HAS_CONTENTS
 [20]     0x006efe08->0x006efff8 at 0x000efe08: .dynamic ALLOC LOAD DATA HAS_CONTENTS
 [21]     0x006efff8->0x006f0000 at 0x000efff8: .got ALLOC LOAD DATA HAS_CONTENTS
 [22]     0x006f0000->0x006f06c0 at 0x000f0000: .got.plt ALLOC LOAD DATA HAS_CONTENTS
 [23]     0x006f06c0->0x006f8ca8 at 0x000f06c0: .data ALLOC LOAD DATA HAS_CONTENTS
 [24]     0x006f8cc0->0x006fe898 at 0x000f8ca8: .bss ALLOC
 [25]     0x00000000->0x0000000c at 0x000f8ca8: .gnu_debuglink READONLY HAS_CONTENTS
"""


class Permission:
    READ = 4
    WRITE = 2
    EXECUTE = 1

    def __init__(self, *args, **kwargs):
        self.value = 0
        return

    def __str__(self):
        perm_str = ""
        perm_str += "r" if self.value & Permission.READ else "-"
        perm_str += "w" if self.value & Permission.WRITE else "-"
        perm_str += "x" if self.value & Permission.EXECUTE else "-"
        return perm_str

    @staticmethod
    def from_info_sections(*args):
        p = Permission()
        for arg in args:
            if "READONLY" in arg:
                p.value += Permission.READ
            if "DATA" in arg:
                p.value += Permission.WRITE
            if "CODE" in arg:
                p.value += Permission.EXECUTE
        return p

    @staticmethod
    def from_process_maps(perm_str):
        p = Permission()
        if perm_str[0] == "r":
            p.value += Permission.READ
        if perm_str[1] == "w":
            p.value += Permission.WRITE
        if perm_str[2] == "x":
            p.value += Permission.EXECUTE
        return p



class Section:
    page_start      = None
    page_end        = None
    offset          = None
    permission      = None
    inode           = None
    path            = None

    def __init__(self, *args, **kwargs):
        attrs = ["page_start", "page_end", "offset", "permission", "inode", "path"]
        for attr in attrs:
            value = kwargs[attr] if attr in kwargs else None
            setattr(self, attr, value)
        return


def get_vmmap_file():
    pass
def parse_vmmap_file_linux():
    pass