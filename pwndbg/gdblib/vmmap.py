"""
Routines to enumerate mapped memory, and attempt to associate
address ranges with various ELF files and permissions.

The reason that we need robustness is that not every operating
system has /proc/$$/maps, which backs 'info proc mapping'.
"""
import bisect
from typing import Any
from typing import List
from typing import Optional
from typing import Tuple

import gdb

import pwndbg.color.message as M
import pwndbg.gdblib.abi
import pwndbg.gdblib.elf
import pwndbg.gdblib.events
import pwndbg.gdblib.file
import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.proc
import pwndbg.gdblib.qemu
import pwndbg.gdblib.regs
import pwndbg.gdblib.remote
import pwndbg.gdblib.stack
import pwndbg.gdblib.typeinfo
import pwndbg.lib.cache

# List of manually-explored pages which were discovered
# by analyzing the stack or register context.
explored_pages: List[pwndbg.lib.memory.Page] = []

# List of custom pages that can be managed manually by vmmap_* commands family
custom_pages: List[pwndbg.lib.memory.Page] = []


kernel_vmmap_via_pt = pwndbg.gdblib.config.add_param(
    "kernel-vmmap-via-page-tables",
    "deprecated",
    "the deprecated config of the method get kernel vmmap",
    help_docstring="Deprecated in favor of `kernel-vmmap`",
)

kernel_vmmap = pwndbg.gdblib.config.add_param(
    "kernel-vmmap",
    "page-tables",
    "the method to get vmmap information when debugging via QEMU kernel",
    help_docstring="""\
kernel-vmmap can be:
page-tables    - read /proc/$qemu-pid/mem to parse kernel page tables to render vmmap
monitor        - use QEMU's `monitor info mem` to render vmmap
none           - disable vmmap rendering; useful if rendering is particularly slow

Note that the page-tables method will require the QEMU kernel process to be on the same machine and within the same PID namespace. Running QEMU kernel and GDB in different Docker containers will not work. Consider running both containers with --pid=host (meaning they will see and so be able to interact with all processes on the machine).
""",
    param_class=gdb.PARAM_ENUM,
    enum_sequence=["page-tables", "monitor", "none"],
)


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
def get() -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Returns a tuple of `Page` objects representing the memory mappings of the
    target, sorted by virtual address ascending.
    """
    # Note: debugging a coredump does still show proc.alive == True
    if not pwndbg.gdblib.proc.alive:
        return tuple()

    if is_corefile():
        return tuple(coredump_maps())

    proc_maps = proc_pid_maps()

    # The `proc_maps` is usually a tuple of Page objects but it can also be:
    #   None    - when /proc/$pid/maps does not exist/is not available
    #   tuple() - when the process has no maps yet which happens only during its very early init
    #             (usually when we attach to a process)
    if proc_maps is not None:
        return proc_maps

    pages = []
    if pwndbg.gdblib.qemu.is_qemu_kernel() and pwndbg.gdblib.arch.current in (
        "i386",
        "x86-64",
        "aarch64",
        "riscv:rv64",
    ):
        # If kernel_vmmap_via_pt is not set to the default value of "deprecated",
        # That means the user was explicitly setting it themselves and need to
        # be warned that the option is deprecated
        if kernel_vmmap_via_pt != "deprecated":
            print(
                M.warn(
                    "`kernel-vmmap-via-page-tables` is deprecated, please use `kernel-vmmap` instead."
                )
            )

        if kernel_vmmap == "page-tables":
            pages.extend(kernel_vmmap_via_page_tables())
        elif kernel_vmmap == "monitor":
            pages.extend(kernel_vmmap_via_monitor_info_mem())

    # TODO/FIXME: Add tests for  QEMU-user targets when this is needed
    if not pages:
        # If debuggee is launched from a symlink the debuggee memory maps will be
        # labeled with symlink path while in normal scenario the /proc/pid/maps
        # labels debuggee memory maps with real path (after symlinks).
        # This is because the exe path in AUXV (and so `info auxv`) is before
        # following links.
        pages.extend(info_auxv())

        if pages:
            pages.extend(info_sharedlibrary())
        else:
            if pwndbg.gdblib.qemu.is_qemu():
                return (pwndbg.lib.memory.Page(0, pwndbg.gdblib.arch.ptrmask, 7, 0, "[qemu]"),)
            pages.extend(info_files())

        pages.extend(pwndbg.gdblib.stack.stacks.values())

    pages.extend(explored_pages)
    pages.extend(custom_pages)
    pages.sort()
    return tuple(pages)


@pwndbg.lib.cache.cache_until("stop")
def find(address):
    if address is None:
        return None

    address = int(address)

    for page in get():
        if address in page:
            return page

    return explore(address)


@pwndbg.gdblib.abi.LinuxOnly()
def explore(address_maybe: int) -> Optional[Any]:
    """
    Given a potential address, check to see what permissions it has.

    Returns:
        Page object

    Note:
        Adds the Page object to a persistent list of pages which are
        only reset when the process dies.  This means pages which are
        added this way will not be removed when unmapped.

        Also assumes the entire contiguous section has the same permission.
    """
    if proc_pid_maps():
        return None

    address_maybe = pwndbg.lib.memory.page_align(address_maybe)

    flags = 4 if pwndbg.gdblib.memory.peek(address_maybe) else 0

    if not flags:
        return None

    flags |= 2 if pwndbg.gdblib.memory.poke(address_maybe) else 0
    flags |= 1 if not pwndbg.gdblib.stack.nx else 0

    page = find_boundaries(address_maybe)
    page.objfile = "<explored>"
    page.flags = flags

    explored_pages.append(page)

    return page


# Automatically ensure that all registers are explored on each stop
# @pwndbg.gdblib.events.stop
def explore_registers() -> None:
    for regname in pwndbg.gdblib.regs.common:
        find(pwndbg.gdblib.regs[regname])


# @pwndbg.gdblib.events.exit
def clear_explored_pages() -> None:
    while explored_pages:
        explored_pages.pop()


def add_custom_page(page) -> None:
    bisect.insort(custom_pages, page)

    # Reset all the cache
    # We can not reset get() only, since the result may be used by others.
    # TODO: avoid flush all caches
    pwndbg.lib.cache.clear_caches()


def clear_custom_page() -> None:
    while custom_pages:
        custom_pages.pop()

    # Reset all the cache
    # We can not reset get() only, since the result may be used by others.
    # TODO: avoid flush all caches
    pwndbg.lib.cache.clear_caches()


@pwndbg.lib.cache.cache_until("objfile", "start")
def coredump_maps():
    """
    Parses `info proc mappings` and `maintenance info sections`
    and tries to make sense out of the result :)
    """
    pages = []

    try:
        info_proc_mappings = pwndbg.gdblib.info.proc_mappings().splitlines()
    except gdb.error:
        # On qemu user emulation, we may get: gdb.error: Not supported on this target.
        info_proc_mappings = []

    for line in info_proc_mappings:
        # We look for lines like:
        # ['0x555555555000', '0x555555556000', '0x1000', '0x1000', '/home/user/a.out']
        try:
            start, _end, size, offset, objfile = line.split()
            start, size, offset = int(start, 16), int(size, 16), int(offset, 16)
        except (IndexError, ValueError):
            continue

        # Note: we set flags=0 because we do not have this information here
        pages.append(pwndbg.lib.memory.Page(start, size, 0, offset, objfile))

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
            start, end = map(lambda v: int(v, 16), start_end.split("->"))

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
        return tuple()

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
            except Exception as e:
                pass
            break

    if stack_addr is not None:
        for page in pages:
            if stack_addr in page:
                page.objfile = "[stack]"
                page.flags |= 6
                page.offset = 0
                break

    return tuple(pages)


@pwndbg.lib.cache.cache_until("start", "stop")
def proc_pid_maps():
    """
    Parse the contents of /proc/$PID/maps on the server.

    Returns:
        A tuple of pwndbg.lib.memory.Page objects or None if
        /proc/$pid/maps doesn't exist or when we debug a qemu-user target
    """

    # If we debug remotely a qemu-user or qemu-system target,
    # there is no point of hitting things further
    if pwndbg.gdblib.qemu.is_qemu():
        return None

    # Example /proc/$pid/maps
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

    pid = pwndbg.gdblib.proc.pid
    locations = [
        f"/proc/{pid}/maps",
        f"/proc/{pid}/map",
        f"/usr/compat/linux/proc/{pid}/maps",
    ]

    for location in locations:
        try:
            data = pwndbg.gdblib.file.get(location).decode()
            break
        except (OSError, gdb.error):
            continue
    else:
        return None

    # Process hasn't been fully created yet; it is in Z (zombie) state
    if data == "":
        return tuple()

    pages = []
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
def kernel_vmmap_via_page_tables():
    import pt

    retpages: List[pwndbg.lib.memory.Page] = []

    p = pt.PageTableDump()
    try:
        p.lazy_init()
    except PermissionError:
        print(
            M.error(
                "Permission error when attempting to parse page tables with gdb-pt-dump.\n"
                + "Either change the kernel-vmmap setting, re-run GDB as root, or disable `ptrace_scope` (`echo 0 | sudo tee /proc/sys/kernel/yama`)"
            )
        )
        return tuple(retpages)

    # If paging is not enabled, we shouldn't attempt to parse page tables
    if not pwndbg.gdblib.kernel.paging_enabled():
        return tuple(retpages)

    pages = p.backend.parse_tables(p.cache, p.parser.parse_args(""))

    for page in pages:
        start = page.va
        size = page.page_size
        flags = 4  # IMPLY ALWAYS READ
        if page.pwndbg_is_writeable():
            flags |= 2
        if page.pwndbg_is_executable():
            flags |= 1
        retpages.append(pwndbg.lib.memory.Page(start, size, flags, 0, "<pt>"))
    return tuple(retpages)


monitor_info_mem_not_warned = True


def kernel_vmmap_via_monitor_info_mem():
    """
    Returns Linux memory maps information by parsing `monitor info mem` output
    from QEMU kernel GDB stub.
    Works only on X86/X64/RISC-V as this is what QEMU supports.

    Consider using the `kernel_vmmap_via_page_tables` method
    as it is probably more reliable/better.

    See also: https://github.com/pwndbg/pwndbg/pull/685
    (TODO: revisit with future QEMU versions)

    # Example output from the command:
    # pwndbg> monitor info mem
    # ffff903580000000-ffff903580099000 0000000000099000 -rw
    # ffff903580099000-ffff90358009b000 0000000000002000 -r-
    # ffff90358009b000-ffff903582200000 0000000002165000 -rw
    # ffff903582200000-ffff903582803000 0000000000603000 -r-
    """
    global monitor_info_mem_not_warned
    monitor_info_mem = None
    try:
        monitor_info_mem = gdb.execute("monitor info mem", to_string=True)
    finally:
        # Older versions of QEMU/GDB may throw `gdb.error: "monitor" command
        # not supported by this target`. Newer versions will not throw, but will
        # return a string starting with 'unknown command:'. We handle both of
        # these cases in a `finally` block instead of an `except` block.
        if monitor_info_mem is None or "unknown command" in monitor_info_mem:
            # TODO: Find out which other architectures don't support this command
            if pwndbg.gdblib.arch.name == "aarch64":
                print(
                    M.error(
                        f"The {pwndbg.gdblib.arch.name} architecture does"
                        + " not support the `monitor info mem` command. Run "
                        + "`help show kernel-vmmap` for other options."
                    )
                )
            return tuple()  # pylint: disable=lost-exception

    lines = monitor_info_mem.splitlines()

    # Handle disabled PG
    # This will prevent a crash on abstract architectures
    if len(lines) == 1 and lines[0] == "PG disabled":
        return tuple()

    pages = []
    for line in lines:
        dash_idx = line.index("-")
        space_idx = line.index(" ")
        rspace_idx = line.rindex(" ")

        start = int(line[:dash_idx], 16)
        end = int(line[dash_idx + 1 : space_idx], 16)
        size = int(line[space_idx + 1 : rspace_idx], 16)
        if end - start != size and monitor_info_mem_not_warned:
            print(
                M.warn(
                    (
                        "The vmmap output may be incorrect as `monitor info mem` output assertion/assumption\n"
                        "that end-start==size failed. The values are:\n"
                        "end=%#x; start=%#x; size=%#x; end-start=%#x\n"
                        "Note that this warning will not show up again in this Pwndbg/GDB session."
                    )
                    % (end, start, size, end - start)
                )
            )
            monitor_info_mem_not_warned = False
        perm = line[rspace_idx + 1 :]

        flags = 0
        if "r" in perm:
            flags |= 4
        if "w" in perm:
            flags |= 2
        # QEMU does not expose X/NX bit, see #685
        # if 'x' in perm: flags |= 1
        flags |= 1

        pages.append(pwndbg.lib.memory.Page(start, size, flags, 0, "<qemu>"))

    return tuple(pages)


@pwndbg.lib.cache.cache_until("stop")
def info_sharedlibrary():
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

    pages = []

    for line in pwndbg.gdblib.info.sharedlibrary().splitlines():
        if not line.startswith("0x"):
            continue

        tokens = line.split()
        text = int(tokens[0], 16)
        obj = tokens[-1]

        pages.extend(pwndbg.gdblib.elf.map(text, obj))

    return tuple(sorted(pages))


@pwndbg.lib.cache.cache_until("stop")
def info_files():
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

    seen_files = set()
    pages = []
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

        if objfile in seen_files:
            continue
        else:
            seen_files.add(objfile)

        pages.extend(pwndbg.gdblib.elf.map(vaddr, objfile))

    return tuple(pages)


@pwndbg.lib.cache.cache_until("exit")
def info_auxv(skip_exe: bool = False):
    """
    Extracts the name of the executable from the output of the command
    "info auxv". Note that if the executable path is a symlink,
    it is not dereferenced by `info auxv` and we also don't dereference it.

    Arguments:
        skip_exe(bool): Do not return any mappings that belong to the exe.

    Returns:
        A list of pwndbg.lib.memory.Page objects.
    """
    auxv = pwndbg.auxv.get()

    if not auxv:
        return tuple()

    pages = []
    exe_name = auxv.AT_EXECFN or "main.exe"
    entry = auxv.AT_ENTRY
    base = auxv.AT_BASE
    vdso = auxv.AT_SYSINFO_EHDR or auxv.AT_SYSINFO
    phdr = auxv.AT_PHDR

    if not skip_exe and (entry or phdr):
        for addr in [entry, phdr]:
            if not addr:
                continue
            new_pages = pwndbg.gdblib.elf.map(addr, exe_name)
            if new_pages:
                pages.extend(new_pages)
                break

    if base:
        pages.extend(pwndbg.gdblib.elf.map(base, "[linker]"))

    if vdso:
        pages.extend(pwndbg.gdblib.elf.map(vdso, "[vdso]"))

    return tuple(sorted(pages))


def find_boundaries(addr, name: str = "", min: int = 0):
    """
    Given a single address, find all contiguous pages
    which are mapped.
    """
    start = pwndbg.gdblib.memory.find_lower_boundary(addr)
    end = pwndbg.gdblib.memory.find_upper_boundary(addr)

    start = max(start, min)

    return pwndbg.lib.memory.Page(start, end - start, 4, 0, name)


def check_aslr():
    """
    Detects the ASLR status. Returns True, False or None.

    None is returned when we can't detect ASLR.
    """
    # QEMU does not support this concept.
    if pwndbg.gdblib.qemu.is_qemu():
        return None, "Could not detect ASLR on QEMU targets"

    # Systemwide ASLR is disabled
    try:
        data = pwndbg.gdblib.file.get("/proc/sys/kernel/randomize_va_space")
        if b"0" in data:
            return False, "kernel.randomize_va_space == 0"
    except Exception as e:
        print("Could not check ASLR: can't read randomize_va_space")

    # Check the personality of the process
    if pwndbg.gdblib.proc.alive:
        try:
            data = pwndbg.gdblib.file.get("/proc/%i/personality" % pwndbg.gdblib.proc.pid)
            personality = int(data, 16)
            return (personality & 0x40000 == 0), "read status from process' personality"
        except Exception:
            print("Could not check ASLR: can't read process' personality")

    # Just go with whatever GDB says it did.
    #
    # This should usually be identical to the above, but we may not have
    # access to procfs.
    output = gdb.execute("show disable-randomization", to_string=True)
    return ("is off." in output), "show disable-randomization"
