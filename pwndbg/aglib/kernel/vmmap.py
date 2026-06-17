from __future__ import annotations

import sys

from pt.pt import PageTableDump
from pt.pt_aarch64_parse import PT_Aarch64_Backend
from pt.pt_riscv64_parse import PT_RiscV64_Backend
from pt.pt_x86_64_parse import PT_x86_64_Backend

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
import pwndbg.aglib.kernel.paging
import pwndbg.aglib.memory
import pwndbg.aglib.qemu
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.err
import pwndbg.lib.memory
from pwndbg.color import message
from pwndbg.lib.memory import Page


def _get_name(
    sections: tuple[tuple[str | None, int | None], ...] | None, addr: int | None
) -> str | None:
    if addr is None or sections is None:
        return None
    for i in range(len(sections) - 1):
        name, cur = sections[i]
        _, next = sections[i + 1]
        if cur is None or next is None or name is None:
            continue
        if cur <= addr < next:
            return name
    return None


def _apply_address_markers(pages: tuple[Page, ...]) -> None:
    pi = pwndbg.aglib.kernel.arch_paginginfo()
    if pi and pages:
        sections = pi.markers()
        # this is needed for context annotations
        for i, page in enumerate(pages):
            name = _get_name(sections, page.start)
            if name is not None:
                page.objfile = name
        pi.handle_kernel_pages(pages)


def _handle_page_offsets(pages: pwndbg.dbg_mod.MemoryMap) -> None:
    # only handle_offsets when invoked through vmmap command
    kernelrw = (
        pwndbg.aglib.kernel.paging.ArchPagingInfo.KERNELRO,
        pwndbg.aglib.kernel.paging.ArchPagingInfo.KERNELBSS,
    )
    prev_objfile, base = "", 0
    for page in pages.ranges():
        # the check on kernelrw is to make getting offsets for symbols such as `init_creds` more convinient
        if page.objfile not in kernelrw and (not prev_objfile or prev_objfile != page.objfile):
            prev_objfile = page.objfile
            base = page.start
        page.offset = page.start - base
        if len(hex(page.offset)) > 9:
            page.offset = 0


def _get_kernel_stacks() -> list[tuple[int, int, str]]:
    stacks = []
    for task in pwndbg.commands.ktask.get_ktasks():
        for thread in task.threads:
            if thread.stack:
                stacks.append((thread.stack, thread.pid, thread.name))
    return stacks


def _handle_user_stack_and_filepaths(pages: pwndbg.dbg_mod.MemoryMap) -> None:
    task = pwndbg.aglib.kernel.current_task()
    if task is None:
        return
    task = pwndbg.commands.ktask.Kthread(task)
    user_stack = task.user_stack
    for page in pages.ranges():
        if pwndbg.aglib.memory.is_kernel(page.start):
            break
        file = pwndbg.aglib.kernel.ktask.resolve_addr_if_file(task.mm, page.start)
        if file:
            page.objfile = file
        if user_stack and user_stack in page:
            page.objfile = "userland [stack]"


@pwndbg.lib.cache.cache_until("stop")
def annotate(pages: pwndbg.dbg_mod.MemoryMap) -> None:
    try:
        pwndbg.aglib.kernel.ktask.recover_ktask_typeinfo()
    except (pwndbg.lib.err.TypeNotRecoveredError, AttributeError):
        return
    _handle_user_stack_and_filepaths(pages)
    _handle_page_offsets(pages)
    stacks = _get_kernel_stacks()
    if not stacks:
        return
    for page in pages.ranges():
        for stack, pid, name in stacks:
            if stack in page:
                # not starting with [stack is intentional
                page.objfile += f" [pid {pid}: {name}]"
                break


@pwndbg.lib.cache.cache_until("stop")
def kernel_vmmap_via_page_tables() -> tuple[Page, ...]:
    if not pwndbg.aglib.qemu.is_qemu_kernel():
        return ()

    if sys.platform != "linux":
        # QemuMachine requires access to /proc/{qemu-pid}/mem, which is only available on Linux
        return ()

    machine_backend = pwndbg.aglib.qemu.get_qemu_machine(True)
    if machine_backend is None:
        return ()

    arch: str = pwndbg.aglib.arch.name
    ptrsize: int = pwndbg.aglib.arch.ptrsize
    if arch == "aarch64":
        arch_backend = PT_Aarch64_Backend(machine_backend)
    elif arch in {"x86-64", "i386"}:
        arch_backend = PT_x86_64_Backend(machine_backend)
    elif arch == "rv64":
        arch_backend = PT_RiscV64_Backend(machine_backend)
    else:
        print(
            message.error(
                f"The {pwndbg.aglib.arch.name} architecture does"
                " not support the `vmmap_via_page_tables`.\n"
                "Run `help show kernel-vmmap` for other options."
            )
        )
        return ()

    # If paging is not enabled, we shouldn't attempt to parse page tables
    if not pwndbg.aglib.kernel.paging_enabled():
        return ()

    p = PageTableDump(machine_backend, arch_backend)
    pages = p.arch_backend.parse_tables(p.cache, p.parser.parse_args(""))

    retpages: list[Page] = []
    for page in pages:
        start = page.va
        size = page.page_size
        flags = 4  # IMPLY ALWAYS READ
        if page.pwndbg_is_writeable():
            flags |= 2
        if page.pwndbg_is_executable():
            flags |= 1
        objfile = f"[pt_{hex(start)[2:-3]}]"
        retpages.append(Page(start, size, flags, 0, ptrsize, objfile))
    return tuple(retpages)


monitor_info_mem_not_warned = True


def _parser_mem_info_line_x86(line: str) -> Page | None:
    """
    Example response from `info mem`:
    ```
    ffff903580000000-ffff903580099000 0000000000099000 -rw
    ffff903580099000-ffff90358009b000 0000000000002000 -r-
    ffff90358009b000-ffff903582200000 0000000002165000 -rw
    ffff903582200000-ffff903582803000 0000000000603000 -r-
    ```
    """

    dash_idx = line.index("-")
    space_idx = line.index(" ")
    rspace_idx = line.rindex(" ")

    start = int(line[:dash_idx], 16)
    end = int(line[dash_idx + 1 : space_idx], 16)
    size = int(line[space_idx + 1 : rspace_idx], 16)
    perm = line[rspace_idx + 1 :]

    flags = 0
    if "r" in perm:
        flags |= Page.R_OK
    if "w" in perm:
        flags |= Page.W_OK
    if "x" in perm:
        flags |= Page.X_OK

    global monitor_info_mem_not_warned
    if end - start != size and monitor_info_mem_not_warned:
        print(
            message.warn(
                "The vmmap output may be incorrect as `monitor info mem` output assertion/assumption\n"
                "that end-start==size failed. The values are:\n"
                f"end={end:#x}; start={start:#x}; size={size:#x}; end-start={end - start:#x}\n"
                "Note that this warning will not show up again in this Pwndbg/GDB session."
            )
        )
        monitor_info_mem_not_warned = False

    return Page(start, size, flags, 0, pwndbg.aglib.arch.ptrsize, "<qemu>")


def _parser_mem_info_line_riscv64(line: str) -> Page | None:
    """
    Example response from `info mem`:
    ```
    vaddr            paddr            size             attr
    ---------------- ---------------- ---------------- -------
    0000000000010000 00000000feece000 0000000000001000 r-xu-a-
    0000000000011000 00000000fefeb000 0000000000002000 r-xu-a-
    0000000000013000 00000000a0a7a000 0000000000002000 r-xu-a-
    0000000000015000 00000000bfe02000 0000000000002000 r-xu-a-
    ```
    """

    arr = line.split(" ", 3)
    if len(arr) != 4:
        raise ValueError("invalid line format")

    start, _, size, perm = arr
    start = int(start, 16)
    size = int(size, 16)

    flags = 0
    if "r" in perm:
        flags |= Page.R_OK
    if "w" in perm:
        flags |= Page.W_OK
    if "x" in perm:
        flags |= Page.X_OK

    return Page(start, size, flags, 0, pwndbg.aglib.arch.ptrsize, "<qemu>")


@pwndbg.lib.cache.cache_until("stop")
def kernel_vmmap_via_monitor_info_mem() -> tuple[Page, ...]:
    """
    Returns Linux memory maps information by parsing `monitor info mem` output
    from QEMU kernel GDB stub.
    Works only on X86/X64/RISC-V as this is what QEMU supports.

    Consider using the `kernel_vmmap_via_page_tables` method
    as it is probably more reliable/better.

    See also: https://github.com/pwndbg/pwndbg/pull/685
    (TODO: revisit with future QEMU versions)
    """
    if not pwndbg.aglib.qemu.is_qemu_kernel():
        return ()

    try:
        monitor_info_mem = pwndbg.dbg.selected_inferior().send_monitor("info mem")
    except pwndbg.dbg_mod.Error:
        # Exception should not happen in new qemu, can we clean up it?
        # Older versions of QEMU/GDB may throw `gdb.error: "monitor" command
        # not supported by this target`. Newer versions will not throw, but will
        # return a string starting with 'unknown command:'.
        monitor_info_mem = "unknown command"

    parser_func = None
    if pwndbg.aglib.arch.name in ("i386", "x86-64"):
        parser_func = _parser_mem_info_line_x86
    elif pwndbg.aglib.arch.name == "rv64":
        parser_func = _parser_mem_info_line_riscv64

    if parser_func is None or "unknown command" in monitor_info_mem:
        print(
            message.error(
                f"The {pwndbg.aglib.arch.name} architecture does"
                " not support the `monitor info mem` command.\n"
                "Run `help show kernel-vmmap` for other options."
            )
        )
        return ()

    pages: list[Page] = []
    for line in monitor_info_mem.splitlines():
        try:
            page = parser_func(line)
        except Exception:
            # invalid format
            continue
        pages.append(page)

    return tuple(pages)


kernel_vmmap_mode = pwndbg.config.add_param(
    "kernel-vmmap",
    "page-tables",
    "the method to get vmmap information when debugging via QEMU kernel",
    help_docstring="""\
Values explained:

+ `page-tables` - walk page tables to render vmmap
+ `pt-dump` - read /proc/$qemu-pid/mem to parse kernel page tables to render vmmap
+ `monitor` - use QEMU's `monitor info mem` to render vmmap
+ `none` - disable vmmap rendering; useful if rendering is particularly slow

Note that the page-tables method will require the QEMU kernel process to be on the same machine and within the same PID namespace. Running QEMU kernel and GDB in different Docker containers will not work. Consider running both containers with --pid=host (meaning they will see and so be able to interact with all processes on the machine).
""",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["page-tables", "pt-dump", "monitor", "none"],
)


@pwndbg.lib.cache.cache_until("stop")
def kernel_vmmap_pages() -> tuple[Page, ...]:
    mode = str(kernel_vmmap_mode)
    arch_name = pwndbg.aglib.arch.name
    if mode == "page-tables" and arch_name not in ("x86-64", "aarch64"):
        # TODO: remove this by implementing `RiscvPagingInfo`, `RiscvOps`, etc
        print(
            message.warn(
                f"`kernel-vmmap = {mode}` unsupported for {arch_name}, defaulting to `monitor`"
            )
        )
        mode = "monitor"
    match mode:
        case "page-tables":
            # has the user set the pgd with kcurrent?
            # None if not which gets properly handled
            entry = None
            if (kcurrent := pwndbg.commands.kcurrent.get_kcurrent()) is not None:
                entry = kcurrent.pgd
            if pwndbg.aglib.memory.is_kernel(entry):
                entry = pwndbg.aglib.kernel.pagewalk(entry, virt=False).phys
            return pwndbg.aglib.kernel.pagescan(entry)
        case "pt-dump":
            return kernel_vmmap_via_page_tables()
        case "monitor":
            return kernel_vmmap_via_monitor_info_mem()
    return ()


def kernel_vmmap() -> tuple[pwndbg.lib.memory.Page, ...]:
    if not pwndbg.aglib.qemu.is_qemu_kernel():
        return ()

    if pwndbg.aglib.arch.name not in (
        "i386",
        "x86-64",
        "aarch64",
        "rv32",
        "rv64",
    ):
        return ()

    pages = kernel_vmmap_pages()
    _apply_address_markers(pages)
    if kernel_vmmap_mode == "monitor" and pwndbg.aglib.arch.name == "x86-64":
        # TODO: check version here when QEMU displays the x bit for x64
        # see: https://github.com/pwndbg/pwndbg/pull/3020#issuecomment-2914573242
        for page in pages:
            if page.objfile == pwndbg.aglib.kernel.paging.ArchPagingInfo.ESPSTACK:
                continue
            entry = pwndbg.aglib.kernel.pagewalk(page.start).entry
            if entry and entry >> 63 == 0:
                page.flags |= 1

    return tuple(pages)
