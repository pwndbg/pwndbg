"""
Routines to enumerate mapped memory, and attempt to associate
address ranges with various ELF files and permissions.

The reason that we need robustness is that not every operating
system has /proc/$$/maps, which backs 'info proc mapping'.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import suppress

import gdb

import pwndbg.aglib
import pwndbg.aglib.file
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.gdblib.info
import pwndbg.lib.cache
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
    inf = gdb.selected_inferior()
    conn = inf.connection
    if conn is None:
        return False
    if not isinstance(inf.connection, gdb.TargetConnection):
        return False
    return conn.type == "core"


@pwndbg.lib.cache.cache_until("start", "stop")
def get_known_maps() -> tuple[pwndbg.lib.memory.Page, ...] | None:
    """
    Similar to `vmmap.get()`, except only returns maps in cases where
    the mappings are known, like if it's a coredump, or if process
    mappings are available.
    """
    # Note: debugging a coredump does still show proc.alive() == True
    if not pwndbg.aglib.proc.alive():
        return ()

    if is_corefile():
        return tuple(coredump_maps())

    return proc_tid_maps()


def iter_coredump_sections() -> Iterator[pwndbg.lib.memory.Page]:
    lines = gdb.execute("maintenance info sections", to_string=True)
    started_sections = False
    ptrsize = pwndbg.aglib.arch.ptrsize

    for line in lines.splitlines():
        if not started_sections:
            if "Core file:" in line:
                started_sections = True
            continue

        if not line.startswith(" "):
            # End of section
            break

        # We look for lines like:
        # ['[9]', '0x00000000->0x00000150', 'at', '0x00098c40:', '.auxv', 'HAS_CONTENTS']
        # ['[15]', '0x555555555000->0x555555556000', 'at', '0x00001430:', 'load2', 'ALLOC', 'LOAD', 'READONLY', 'CODE', 'HAS_CONTENTS']
        try:
            _idx, start_end, _at_str, _at, section_name, *flags_list = line.split()
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

        page = pwndbg.lib.memory.Page(
            start, end - start, flags, offset, ptrsize, f"[{section_name}]"
        )
        yield page


def enhance_coredump_sections_pages_info(pages: list[pwndbg.lib.memory.Page]) -> None:
    for section in iter_coredump_sections():
        # Now, if the section is already in pages, just add its perms
        known_page = False

        for page in pages:
            if section.start in page:
                page.flags |= section.flags
                known_page = True
                break

        if known_page:
            continue

        pages.append(section)


def enhance_known_pages_info(pages: list[pwndbg.lib.memory.Page]) -> None:
    if not pages:
        return

    # ffffffffff600000-ffffffffff601000
    # If the last page starts on e.g. 0xffffffffff600000 it must be vsyscall
    vsyscall_page = pages[-1]
    if vsyscall_page.start > 0xFFFFFFFFFF000000 and vsyscall_page.flags & 1:
        vsyscall_page.objfile = "[vsyscall]"
        vsyscall_page.offset = 0

    # Detect stack based on addresses in AUXV from stack memory
    stack_addr = None
    vdso_addr = None

    # TODO/FIXME: Can we uxe `pwndbg.auxv.get()` for this somehow?
    auxv = pwndbg.gdblib.info.auxv().splitlines()
    for line in auxv:
        if "AT_EXECFN" in line:
            with suppress(Exception):
                stack_addr = int(line.split()[-2], 16)
        if "AT_SYSINFO_EHDR" in line:
            with suppress(Exception):
                vdso_addr = int(line.split()[-1], 16)

    for page in pages:
        if stack_addr and stack_addr in page:
            page.objfile = "[stack]"
            page.flags |= 6
            page.offset = 0
        if vdso_addr:
            if vdso_addr == page.start:
                page.objfile = "[vdso]"
            elif vdso_addr == page.end:
                page.objfile = "[maybe: vvar/vvar_vclock]"


@pwndbg.lib.cache.cache_until("objfile", "start")
def coredump_maps() -> tuple[pwndbg.lib.memory.Page, ...]:
    """
    Parses `info proc mappings` and `maintenance info sections`
    and tries to make sense out of the result :)
    """
    pages = list(info_proc_maps(parse_flags=False))

    enhance_coredump_sections_pages_info(pages)
    enhance_known_pages_info(pages)

    pages.sort(key=lambda page: page.start)
    return tuple(pages)


def parse_info_proc_mappings_line(
    line: str, perms_available: bool, parse_flags: bool
) -> pwndbg.lib.memory.Page | None:
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

    ptrsize = pwndbg.aglib.arch.ptrsize
    return pwndbg.lib.memory.Page(start, size, flags, offset, ptrsize, objfile)


@pwndbg.lib.cache.cache_until("start", "stop")
def info_proc_maps(parse_flags: bool = True) -> tuple[pwndbg.lib.memory.Page, ...]:
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

    pages: list[pwndbg.lib.memory.Page] = []
    for line in info_proc_mappings:
        page = parse_info_proc_mappings_line(line, perms_available, parse_flags)
        if page is not None:
            pages.append(page)

    return tuple(pages)


def parse_tid_maps_line(line: str) -> pwndbg.lib.memory.Page:
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
    ptrsize: int = pwndbg.aglib.arch.ptrsize
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

    return pwndbg.lib.memory.Page(start, size, flags, offset, ptrsize, objfile)


def parse_tid_maps(data: str) -> list[pwndbg.lib.memory.Page]:
    pages: list[pwndbg.lib.memory.Page] = []
    for line in data.splitlines():
        page = parse_tid_maps_line(line)
        pages.append(page)

    return pages


def parse_tid_smaps_dict(data: list[str]) -> dict[str, list[str]]:
    smaps_dict: dict[str, list[str]] = {}
    for line in data:
        try:
            key, *value = line.strip().split()
            key = key.rstrip(":")
            smaps_dict[key.replace(":", "")] = value
        except ValueError:
            continue

    return smaps_dict


def group_tid_smaps_segments(data: str) -> list[list[str]]:
    # Example segment of /proc/$tid/smaps
    # 7f0bd1c25000-7f0bd1c27000 rw-p 001e8000 00:22 1655096                    /usr/lib64/libc.so.6
    # Size:                  8 kB
    # KernelPageSize:        4 kB
    # MMUPageSize:           4 kB
    # Rss:                   8 kB
    # Pss:                   8 kB
    # Pss_Dirty:             8 kB
    # Shared_Clean:          0 kB
    # Shared_Dirty:          0 kB
    # Private_Clean:         0 kB
    # Private_Dirty:         8 kB
    # Referenced:            8 kB
    # Anonymous:             8 kB
    # KSM:                   0 kB
    # LazyFree:              0 kB
    # AnonHugePages:         0 kB
    # ShmemPmdMapped:        0 kB
    # FilePmdMapped:         0 kB
    # Shared_Hugetlb:        0 kB
    # Private_Hugetlb:       0 kB
    # Swap:                  0 kB
    # SwapPss:               0 kB
    # Locked:                0 kB
    # THPeligible:           0
    # ProtectionKey:         0
    # VmFlags: rd wr mr mw me ac sd
    segments: list[list[str]] = []
    lines = data.splitlines()

    # Group lines into segments by detecting address range lines
    current_segment: list[str] = []

    for line in lines:
        # Check if this line starts with an address range (e.g., "7f0bd1c25000-7f0bd1c27000")
        # An address range line starts with hex digits followed by a dash
        is_address_line = False
        if line and not line[0].isspace():
            # Try to detect if this is an address range line
            try:
                first_token = line.split()[0]
                if "-" in first_token:
                    # Try to parse both parts as hex addresses
                    start, end = first_token.split("-", 1)
                    int(start, 16)
                    int(end, 16)
                    is_address_line = True
            except (ValueError, IndexError):
                pass

        if is_address_line:
            # Process the previous segment if it exists
            if current_segment:
                segments.append(current_segment)

            # Start a new segment
            current_segment = [line]
        else:
            # Add to current segment
            current_segment.append(line)

    # Process the last segment
    if current_segment:
        segments.append(current_segment)

    return segments


def parse_tid_smaps(data: str) -> list[pwndbg.lib.memory.Page]:
    pages: list[pwndbg.lib.memory.Page] = []
    segments = group_tid_smaps_segments(data)
    for segment in segments:
        page = parse_tid_maps_line(segment[0])
        smaps_dict = parse_tid_smaps_dict(segment[1:])
        if "ProtectionKey" in smaps_dict:
            page.protection_key = int(smaps_dict.get("ProtectionKey")[0])
        page.vm_flags = smaps_dict.get("VmFlags")
        pages.append(page)

    return pages


@pwndbg.lib.cache.cache_until("start", "stop")
def proc_tid_maps() -> tuple[pwndbg.lib.memory.Page, ...] | None:
    """
    Parse the contents of /proc/$TID/smaps on the server.
    Falls back to /proc/$TID/maps if smaps is not available.
    (TID == Thread Identifier. We do not use PID since it may not be correct)

    Returns:
        A tuple of pwndbg.lib.memory.Page objects or None if
        /proc/$tid/maps doesn't exist or when we debug a qemu-user target
    """

    # If we debug remotely a qemu-system target,
    # there is no point of hitting things further
    if pwndbg.aglib.qemu.is_qemu_kernel():
        return None

    tid = pwndbg.aglib.proc.tid()
    locations = [
        # Linux distro
        (f"/proc/{tid}/smaps", parse_tid_smaps),
        (f"/proc/{tid}/maps", parse_tid_maps),
        # Freebsd in some cases
        (f"/usr/compat/linux/proc/{tid}/maps", parse_tid_maps),
    ]
    maps_parse_function = None

    for location, parse_fn in locations:
        try:
            data = pwndbg.aglib.file.get(location).decode()
            maps_parse_function = parse_fn
            break
        except OSError:
            continue
    else:
        return None

    # Process hasn't been fully created yet; it is in Z (zombie) state
    if data == "":
        return ()

    pages = maps_parse_function(data)

    return tuple(pages)
