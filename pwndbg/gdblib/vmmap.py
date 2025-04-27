"""
Routines to enumerate mapped memory, and attempt to associate
address ranges with various ELF files and permissions.

The reason that we need robustness is that not every operating
system has /proc/$$/maps, which backs 'info proc mapping'.
"""

from __future__ import annotations

from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import gdb

import pwndbg
import pwndbg.aglib.elf
import pwndbg.aglib.file
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.auxv
import pwndbg.gdblib.info
import pwndbg.lib.cache
import pwndbg.lib.config
import pwndbg.lib.memory


@pwndbg.lib.cache.cache_until("objfile", "start")
def is_corefile() -> bool:
    """
    For example output use:
        gdb ./tests/binaries/crash_simple.out -ex run -ex 'generate-core-file ./core' -ex 'quit'

    And then use:
        gdb ./tests/binaries/crash_simple.out -core ./core -ex 'info target'
    And:
        gdb -core ./core

    As the two differ in output slighty.
    """
    return "Local core dump file:\n" in pwndbg.gdblib.info.target()


@pwndbg.lib.cache.cache_until("start", "stop")
def get_known_maps() -> Tuple[pwndbg.lib.memory.Page, ...] | None:
    """
    Similar to `vmmap.get()`, except only returns maps in cases where
    the mappings are known, like if it's a coredump, or if process
    mappings are available.
    """
    # Note: debugging a coredump does still show proc.alive == True
    if not pwndbg.aglib.proc.alive:
        return ()

    if is_corefile():
        return tuple(coredump_maps())

    return proc_tid_maps()


@pwndbg.lib.cache.cache_until("objfile", "start")
def coredump_maps() -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Parses `info proc mappings` and `maintenance info sections`
    and tries to make sense out of the result :)
    """
    pages = list(info_proc_maps(parse_flags=False))

    started_sections = False
    for line in gdb.execute("maintenance info sections", to_string=True).splitlines():
        if not started_sections:
            if "Core file:" in line:
                started_sections = True
            continue

        # We look for lines like:
        # ['[9]', '0x00000000->0x00000150', 'at', '0x00098c40:', '.auxv', 'HAS_CONTENTS']
        # ['[15]', '0x555555555000->0x555555556000', 'at', '0x00001430:', 'load2', 'ALLOC', 'LOAD', 'READONLY', 'CODE', 'HAS_CONTENTS']
        try:
            _idx, start_end, _at_str, _at, name, *flags_list = line.split()
            start, end = (int(v, 16) for v in start_end.split("->"))

            # Skip pages with start=0x0, this is unlikely this is valid vmmap
            if start == 0:
                continue

            # Tried taking this from the 'at 0x...' value
            # but it turns out to be invalid, so keep it 0 until we find better way
            offset = 0
        except (IndexError, ValueError):
            continue

        # Note: can we deduce anything from 'ALLOC', 'HAS_CONTENTS' or 'LOAD' flags?
        flags = 0
        if "READONLY" in flags_list:
            flags |= 4
        if "DATA" in flags_list:
            flags |= 2
        if "CODE" in flags_list:
            flags |= 1

        # Now, if the section is already in pages, just add its perms
        known_page = False

        for page in pages:
            if start in page:
                page.flags |= flags
                known_page = True
                break

        if known_page:
            continue

        pages.append(pwndbg.lib.memory.Page(start, end - start, flags, offset, name))

    if not pages:
        return ()

    # If the last page starts on e.g. 0xffffffffff600000 it must be vsyscall
    vsyscall_page = pages[-1]
    if vsyscall_page.start > 0xFFFFFFFFFF000000 and vsyscall_page.flags & 1:
        vsyscall_page.objfile = "[vsyscall]"
        vsyscall_page.offset = 0

    # Detect stack based on addresses in AUXV from stack memory
    stack_addr = None

    # TODO/FIXME: Can we uxe `pwndbg.auxv.get()` for this somehow?
    auxv = pwndbg.gdblib.info.auxv().splitlines()
    for line in auxv:
        if "AT_EXECFN" in line:
            try:
                stack_addr = int(line.split()[-2], 16)
            except Exception:
                pass
            break

    if stack_addr is not None:
        for page in pages:
            if stack_addr in page:
                page.objfile = "[stack]"
                page.flags |= 6
                page.offset = 0
                break

    pages.sort(key=lambda page: page.start)
    return tuple(pages)


def parse_info_proc_mappings_line(
    line: str, perms_available: bool, parse_flags: bool
) -> Optional[pwndbg.lib.memory.Page]:
    """
    Parse a line from `info proc mappings` and return a pwndbg.lib.memory.Page
    object if the line is valid.

    Example lines:
        0x4c3000           0x4c5000     0x2000    0xc2000  rw-p   /root/hello_world/main
        0x4c5000           0x4cb000     0x6000        0x0  rw-p

    The objfile column might be empty, and the permissions column is only present in GDB versions >= 12.1
    https://github.com/bminor/binutils-gdb/commit/29ef4c0699e1b46d41ade00ae07a54f979ea21cc

    Args:
        line: A line from `info proc mappings`.

    Returns:
        A pwndbg.lib.memory.Page object or None.
    """
    try:
        # Example line with all fields present: ['0x555555555000', '0x555555556000', '0x1000', '0x1000', 'rw-p', '/home/user/a.out']
        split_line = line.split()

        start_str = split_line[0]
        _end = split_line[1]
        size_str = split_line[2]
        offset_str = split_line[3]

        if perms_available:
            perm = split_line[4]
            # The objfile column may be empty.
            objfile = split_line[5] if len(split_line) > 5 else ""
        else:
            perm = "rwxp"
            objfile = split_line[4] if len(split_line) > 4 else ""

        start, size, offset = int(start_str, 16), int(size_str, 16), int(offset_str, 16)
    except (IndexError, ValueError):
        return None

    flags = 0
    if parse_flags:
        if "r" in perm:
            flags |= 4
        if "w" in perm:
            flags |= 2
        if "x" in perm:
            flags |= 1

    return pwndbg.lib.memory.Page(start, size, flags, offset, objfile)


@pwndbg.lib.cache.cache_until("start", "stop")
def info_proc_maps(parse_flags=True) -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Parse the result of info proc mappings.

    Example output:

            Start Addr           End Addr       Size     Offset  Perms  objfile
              0x400000           0x401000     0x1000        0x0  r--p   /root/hello_world/main
              0x401000           0x497000    0x96000     0x1000  r-xp   /root/hello_world/main
              0x497000           0x4be000    0x27000    0x97000  r--p   /root/hello_world/main
              0x4be000           0x4c3000     0x5000    0xbd000  r--p   /root/hello_world/main
              0x4c3000           0x4c5000     0x2000    0xc2000  rw-p   /root/hello_world/main
              0x4c5000           0x4cb000     0x6000        0x0  rw-p
              0x4cb000           0x4ed000    0x22000        0x0  rw-p   [heap]
        0x7ffff7ff9000     0x7ffff7ffd000     0x4000        0x0  r--p   [vvar]
        0x7ffff7ffd000     0x7ffff7fff000     0x2000        0x0  r-xp   [vdso]
        0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]
    0xffffffffff600000 0xffffffffff601000     0x1000        0x0  --xp   [vsyscall]

    Note: this may return no pages due to a bug/behavior of GDB.
    See https://sourceware.org/bugzilla/show_bug.cgi?id=31207
    for more information.

    Returns:
        A tuple of pwndbg.lib.memory.Page objects or an empty tuple if
        info proc mapping is not supported on the target.
    """

    try:
        info_proc_mappings = pwndbg.gdblib.info.proc_mappings().splitlines()
    except gdb.error:
        # On qemu user emulation, we may get: gdb.error: Not supported on this target.
        info_proc_mappings = []

    # See if "Perms" is in the header line
    perms_available = len(info_proc_mappings) >= 4 and "Perms" in info_proc_mappings[3]

    pages: List[pwndbg.lib.memory.Page] = []
    for line in info_proc_mappings:
        page = parse_info_proc_mappings_line(line, perms_available, parse_flags)
        if page is not None:
            pages.append(page)

    return tuple(pages)


@pwndbg.lib.cache.cache_until("start", "stop")
def proc_tid_maps() -> Tuple[pwndbg.lib.memory.Page, ...] | None:
    """
    Parse the contents of /proc/$TID/maps on the server.
    (TID == Thread Identifier. We do not use PID since it may not be correct)

    Returns:
        A tuple of pwndbg.lib.memory.Page objects or None if
        /proc/$tid/maps doesn't exist or when we debug a qemu-user target
    """

    # If we debug remotely a qemu-system target,
    # there is no point of hitting things further
    if pwndbg.aglib.qemu.is_qemu_kernel():
        return None

    # Example /proc/$tid/maps
    # 7f95266fa000-7f95268b5000 r-xp 00000000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f95268b5000-7f9526ab5000 ---p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f9526ab5000-7f9526ab9000 r--p 001bb000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f9526ab9000-7f9526abb000 rw-p 001bf000 08:01 418404                     /lib/x86_64-linux-gnu/libc-2.19.so
    # 7f9526abb000-7f9526ac0000 rw-p 00000000 00:00 0
    # 7f9526ac0000-7f9526ae3000 r-xp 00000000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    # 7f9526cbe000-7f9526cc1000 rw-p 00000000 00:00 0
    # 7f9526ce0000-7f9526ce2000 rw-p 00000000 00:00 0
    # 7f9526ce2000-7f9526ce3000 r--p 00022000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    # 7f9526ce3000-7f9526ce4000 rw-p 00023000 08:01 418153                     /lib/x86_64-linux-gnu/ld-2.19.so
    # 7f9526ce4000-7f9526ce5000 rw-p 00000000 00:00 0
    # 7f9526ce5000-7f9526d01000 r-xp 00000000 08:01 786466                     /bin/dash
    # 7f9526f00000-7f9526f02000 r--p 0001b000 08:01 786466                     /bin/dash
    # 7f9526f02000-7f9526f03000 rw-p 0001d000 08:01 786466                     /bin/dash
    # 7f9526f03000-7f9526f05000 rw-p 00000000 00:00 0
    # 7f95279fe000-7f9527a1f000 rw-p 00000000 00:00 0                          [heap]
    # 7fff3c177000-7fff3c199000 rw-p 00000000 00:00 0                          [stack]
    # 7fff3c1e8000-7fff3c1ea000 r-xp 00000000 00:00 0                          [vdso]
    # ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

    tid = pwndbg.aglib.proc.tid
    locations = [
        # Linux distro
        f"/proc/{tid}/maps",
        # Freebsd in some cases
        f"/usr/compat/linux/proc/{tid}/maps",
    ]

    for location in locations:
        try:
            data = pwndbg.aglib.file.get(location).decode()
            break
        except OSError:
            continue
    else:
        return None

    # Process hasn't been fully created yet; it is in Z (zombie) state
    if data == "":
        return ()

    pages: List[pwndbg.lib.memory.Page] = []
    for line in data.splitlines():
        maps, perm, offset, dev, inode_objfile = line.split(maxsplit=4)

        start, stop = maps.split("-")

        try:
            inode, objfile = inode_objfile.split(maxsplit=1)
        except Exception:
            # Name unnamed anonymous pages so they can be used e.g. with search commands
            objfile = "[anon_" + start[:-3] + "]"

        start = int(start, 16)
        stop = int(stop, 16)
        offset = int(offset, 16)
        size = stop - start

        flags = 0
        if "r" in perm:
            flags |= 4
        if "w" in perm:
            flags |= 2
        if "x" in perm:
            flags |= 1

        page = pwndbg.lib.memory.Page(start, size, flags, offset, objfile)
        pages.append(page)

    return tuple(pages)


@pwndbg.lib.cache.cache_until("stop")
def info_sharedlibrary() -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Parses the output of `info sharedlibrary`.

    Specifically, all we really want is any valid pointer into each library,
    and the path to the library on disk.

    With this information, we can use the ELF parser to get all of the
    page permissions for every mapped page in the ELF.

    Returns:
        A list of pwndbg.lib.memory.Page objects.
    """

    # Example of `info sharedlibrary` on FreeBSD
    # From        To          Syms Read   Shared Object Library
    # 0x280fbea0  0x2810e570  Yes (*)     /libexec/ld-elf.so.1
    # 0x281260a0  0x281495c0  Yes (*)     /lib/libncurses.so.8
    # 0x28158390  0x2815dcf0  Yes (*)     /usr/local/lib/libintl.so.9
    # 0x28188b00  0x2828e060  Yes (*)     /lib/libc.so.7
    # (*): Shared library is missing debugging information.

    # Example of `info sharedlibrary` on Linux
    # From                To                  Syms Read   Shared Object Library
    # 0x00007ffff7ddaae0  0x00007ffff7df54e0  Yes         /lib64/ld-linux-x86-64.so.2
    # 0x00007ffff7bbd3d0  0x00007ffff7bc9028  Yes (*)     /lib/x86_64-linux-gnu/libtinfo.so.5
    # 0x00007ffff79aded0  0x00007ffff79ae9ce  Yes         /lib/x86_64-linux-gnu/libdl.so.2
    # 0x00007ffff76064a0  0x00007ffff774c113  Yes         /lib/x86_64-linux-gnu/libc.so.6
    # (*): Shared library is missing debugging information.

    pages: List[pwndbg.lib.memory.Page] = []

    for line in pwndbg.gdblib.info.sharedlibrary().splitlines():
        if not line.startswith("0x"):
            continue

        tokens = line.split()
        text = int(tokens[0], 16)
        obj = tokens[-1]

        pages.extend(pwndbg.aglib.elf.map(text, obj))

    return tuple(sorted(pages))


@pwndbg.lib.cache.cache_until("stop")
def info_files() -> Tuple[pwndbg.lib.memory.Page, ...]:
    # Example of `info files` output:
    # Symbols from "/bin/bash".
    # Unix child process:
    # Using the running image of child process 5903.
    # While running this, GDB does not access memory from...
    # Local exec file:
    # `/bin/bash', file type elf64-x86-64.
    # Entry point: 0x42020b
    # 0x0000000000400238 - 0x0000000000400254 is .interp
    # 0x0000000000400254 - 0x0000000000400274 is .note.ABI-tag
    # ...
    # 0x00000000006f06c0 - 0x00000000006f8ca8 is .data
    # 0x00000000006f8cc0 - 0x00000000006fe898 is .bss
    # 0x00007ffff7dda1c8 - 0x00007ffff7dda1ec is .note.gnu.build-id in /lib64/ld-linux-x86-64.so.2
    # 0x00007ffff7dda1f0 - 0x00007ffff7dda2ac is .hash in /lib64/ld-linux-x86-64.so.2
    # 0x00007ffff7dda2b0 - 0x00007ffff7dda38c is .gnu.hash in /lib64/ld-linux-x86-64.so.2

    seen_files: Set[str] = set()
    pages: List[pwndbg.lib.memory.Page] = []
    main_exe = ""

    for line in pwndbg.gdblib.info.files().splitlines():
        line = line.strip()

        # The name of the main executable
        if line.startswith("`"):
            exename, filetype = line.split(maxsplit=1)
            main_exe = exename.strip("`,'")
            continue

        # Everything else should be addresses
        if not line.startswith("0x"):
            continue

        # start, stop, _, segment, _, filename = line.split(maxsplit=6)
        fields = line.split(maxsplit=6)
        vaddr = int(fields[0], 16)

        if len(fields) == 5:
            objfile = main_exe
        elif len(fields) == 7:
            objfile = fields[6]
        else:
            print("Bad data: %r" % line)
            continue

        if objfile not in seen_files:
            seen_files.add(objfile)

        pages.extend(pwndbg.aglib.elf.map(vaddr, objfile))

    return tuple(pages)


@pwndbg.lib.cache.cache_until("exit")
def info_auxv(skip_exe: bool = False) -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Extracts the name of the executable from the output of the command
    "info auxv". Note that if the executable path is a symlink,
    it is not dereferenced by `info auxv` and we also don't dereference it.

    Arguments:
        skip_exe: Do not return any mappings that belong to the exe.

    Returns:
        A list of pwndbg.lib.memory.Page objects.
    """
    auxv = pwndbg.auxv.get()

    if not auxv:
        return ()

    pages: List[pwndbg.lib.memory.Page] = []
    exe_name = auxv.AT_EXECFN or "main.exe"
    entry = auxv.AT_ENTRY
    base = auxv.AT_BASE
    vdso = auxv.AT_SYSINFO_EHDR or auxv.AT_SYSINFO
    phdr = auxv.AT_PHDR

    if not skip_exe and (entry or phdr):
        for addr in [entry, phdr]:
            if not addr:
                continue
            new_pages = pwndbg.aglib.elf.map(addr, exe_name)
            if new_pages:
                pages.extend(new_pages)
                break

    if base:
        pages.extend(pwndbg.aglib.elf.map(base, "[linker]"))

    if vdso:
        pages.extend(pwndbg.aglib.elf.map(vdso, "[vdso]"))

    return tuple(sorted(pages))
