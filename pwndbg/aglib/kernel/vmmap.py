from __future__ import annotations

import os
import random
import string
import subprocess
import sys
import tempfile
from typing import List
from typing import Tuple

from pt.machine import Machine
from pt.pt import PageTableDump
from pt.pt_aarch64_parse import PT_Aarch64_Backend
from pt.pt_riscv64_parse import PT_RiscV64_Backend
from pt.pt_x86_64_parse import PT_x86_64_Backend

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.paging
import pwndbg.aglib.qemu
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.memory


class KernelVmmap:
    USERLAND = "userland"
    KERNELLAND = "kernel [.text]"
    KERNELRO = "kernel [.rodata]"
    KERNELBSS = "kernel [.bss]"
    KERNELDRIVER = "kernel [.driver .bpf]"
    ESPSTACK = "%esp fixup"

    def __init__(self, pages: Tuple[pwndbg.lib.memory.Page, ...]):
        self.pages = pages
        self.sections = None
        if not pwndbg.aglib.kernel.has_debug_syms():
            return
        self.kbase = kbase = pwndbg.aglib.kernel.paging.find_kbase(pages)
        if pwndbg.aglib.arch.name == "x86-64":
            # https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
            # works for v5.x and v6.x
            physmap = pwndbg.aglib.kernel.paging.physmap_base()
            if physmap is None:  # what??
                return
            vmalloc = pwndbg.aglib.symbol.lookup_symbol_value("vmalloc_base")
            vmemmap = pwndbg.aglib.symbol.lookup_symbol_value("vmemmap_base")
            self.sections = (
                (self.USERLAND, 0),
                (None, 0x8000000000000000),
                ("physmap", physmap),
                ("vmalloc", vmalloc),
                ("vmemmap", vmemmap),
                # TODO: find better ways to handle the following constants
                #   I cound not find kernel symbols that reference their values
                #   the actual region base may differ but the region always falls within the below range
                #   even if KASLR is enabled
                ("cpu entry", 0xFFFFFE0000000000),
                ("rand cpu entry", 0xFFFFFE0000001000),
                (self.ESPSTACK, 0xFFFFFF0000000000),
                ("EFI", 0xFFFFFFEF00000000),
                (self.KERNELLAND, kbase),
                ("fixmap", 0xFFFFFFFFFF000000),
                ("legacy abi", 0xFFFFFFFFFF600000),
                (None, 0xFFFFFFFFFFFFFFFF),
            )
        if pwndbg.aglib.arch.name == "aarch64":
            # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
            # https://elixir.bootlin.com/linux/v6.15/source/arch/arm64/mm/ptdump.c#L351
            # TODO: I don't think those are necessarily accurate when KASLR is enabled
            #       but I'm not familiar with ARM enough quite yet to find better ways
            address_markers = pwndbg.aglib.symbol.lookup_symbol_addr("address_markers")
            if address_markers is None:
                return
            sections = [(self.USERLAND, 0)]
            value = 0
            name = None
            for i in range(20):
                value = pwndbg.aglib.memory.u64(address_markers + i * 0x10)
                if value > 0:
                    name_ptr = pwndbg.aglib.memory.u64(address_markers + i * 0x10 + 8)
                    name = None
                    if name_ptr > 0:
                        name = pwndbg.aglib.memory.string(name_ptr).decode()
                        name = name.split(" ")[0].lower()
                        if "end" in name:
                            name = None
                        if name == "linear":
                            name = "physmap"
                sections.append((name, value))
                if value == 0xFFFFFFFFFFFFFFFF:
                    break
            self.sections = tuple(sections)

    def get_name(self, addr: int) -> str:
        if addr is None or self.sections is None:
            return None
        for i in range(len(self.sections) - 1):
            name, cur = self.sections[i]
            _, next = self.sections[i + 1]
            if cur is None or next is None:
                continue
            if addr >= cur and addr < next:
                return name
        return None

    def adjust(self):
        for i, page in enumerate(self.pages):
            name = self.get_name(page.start)
            if name is not None:
                page.objfile = name
        user_idx, kernel_idx = None, None
        for i, page in enumerate(self.pages):
            if user_idx is None and page.objfile == self.USERLAND:
                user_idx = i
            if kernel_idx is None and page.objfile == self.KERNELLAND:
                kernel_idx = i
        self.handle_user_pages(user_idx)
        self.handle_kernel_pages(kernel_idx)
        self.handle_offsets()

    def handle_user_pages(self, user_idx):
        if user_idx is None:
            return
        base_offset = self.pages[user_idx].start
        for i in range(user_idx, len(self.pages)):
            page = self.pages[i]
            if page.objfile != self.USERLAND:
                break
            diff = page.start - base_offset
            if diff > 0x100000:
                if diff > 0x100000000000:
                    if page.execute:
                        page.objfile = "userland [library]"
                    elif page.rw:
                        page.objfile = "userland [stack]"
                else:
                    page.objfile = "userland [heap]"
            else:
                # page.objfile += f"_{hex(i)[2:]}"
                base_offset = page.start

    def handle_kernel_pages(self, kernel_idx):
        if kernel_idx is None:
            return
        has_loadable_driver = False
        for i in range(kernel_idx, len(self.pages)):
            page = self.pages[i]
            if page.objfile != self.KERNELLAND:
                break
            if not page.execute:
                if page.write:
                    page.objfile = self.KERNELBSS
                else:
                    page.objfile = self.KERNELRO
            if has_loadable_driver:
                page.objfile = self.KERNELDRIVER
            if page.execute and page.start != self.kbase:
                page.objfile = self.KERNELDRIVER
                has_loadable_driver = True
            if pwndbg.aglib.regs[pwndbg.aglib.regs.stack] in page:
                page.objfile = "kernel [stack]"

    def handle_offsets(self):
        prev_objfile, base = "", 0
        for page in self.pages:
            # the check on KERNELRO is to make getting offsets for symbols such as `init_creds` more convinient
            if page.objfile != self.KERNELRO and prev_objfile != page.objfile:
                prev_objfile = page.objfile
                base = page.start
            page.offset = page.start - base
            if len(hex(page.offset)) > 9:
                page.offset = 0


# Most of QemuMachine code was inherited from gdb-pt-dump thanks to Martin Radev (@martinradev)
# on the MIT license, see:
# https://github.com/martinradev/gdb-pt-dump/blob/21158ac3f9b36d0e5e0c86193e0ef018fc628e74/pt_gdb/pt_gdb.py#L11-L80
class QemuMachine(Machine):
    def __init__(self):
        super().__init__()
        self.file = None
        self.pid = QemuMachine.get_qemu_pid()
        self.file = os.open(f"/proc/{self.pid}/mem", os.O_RDONLY)

    def __del__(self):
        if self.file:
            os.close(self.file)

    @staticmethod
    def search_pids_for_file(pids: List[str], filename: str) -> str | None:
        for pid in pids:
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    if os.readlink(f"{fd_dir}/{fd}") == filename:
                        return pid
            except FileNotFoundError:
                # Either the process has gone or fds are changing, not our pid
                pass
            except PermissionError:
                # Evade processes owned by other users
                pass

        return None

    @staticmethod
    def get_qemu_pid():
        try:
            out = subprocess.check_output(["pgrep", "qemu-system"], encoding="utf8")
            pids = out.strip().split("\n")

            if len(pids) == 1:
                return int(pids[0], 10)
        except subprocess.CalledProcessError:
            # If no process with the name `qemu-system` is found, fallback to alternative methods,
            # as the binary name may vary (e.g., `qemu_system`).
            pass

        # We add a chardev file backend (we dont add a fronted, so it doesn't affect
        # the guest). We can then look through proc to find which process has the file
        # open. This approach is agnostic to namespaces (pid, network and mount).
        chardev_id = "gdb-pt-dump" + "-" + "".join(random.choices(string.ascii_letters, k=16))
        with tempfile.NamedTemporaryFile() as tmpf:
            pwndbg.dbg.selected_inferior().send_monitor(
                f"chardev-add file,id={chardev_id},path={tmpf.name}"
            )
            pid_found = QemuMachine.search_pids_for_file(pids, tmpf.name)
            pwndbg.dbg.selected_inferior().send_monitor(f"chardev-remove {chardev_id}")

        if not pid_found:
            raise ProcessLookupError("Could not find qemu-system pid")

        return int(pid_found, 10)

    def read_physical_memory(self, physical_address: int, length: int) -> bytes:
        res = pwndbg.dbg.selected_inferior().send_monitor(f"gpa2hva {hex(physical_address)}")

        # It's not possible to pread large sizes, so let's break the request
        # into a few smaller ones.
        max_block_size = 1024 * 1024 * 256
        try:
            hva = int(res.split(" ")[-1], 16)
            data = b""
            for offset in range(0, length, max_block_size):
                length_to_read = min(length - offset, max_block_size)
                block = os.pread(self.file, length_to_read, hva + offset)
                data += block
            return data
        except Exception as e:
            msg = f"Physical address ({hex(physical_address)}, +{hex(length)}) is not accessible. Reason: {e}. gpa2hva result: {res}"
            raise OSError(msg)

    def read_register(self, register_name: str) -> int:
        if register_name.startswith("$"):
            register_name = register_name[1:]

        return int(getattr(pwndbg.aglib.regs, register_name))


@pwndbg.lib.cache.cache_until("stop")
def kernel_vmmap_via_page_tables() -> Tuple[pwndbg.lib.memory.Page, ...]:
    if not pwndbg.aglib.qemu.is_qemu_kernel():
        return ()

    if sys.platform != "linux":
        # QemuMachine requires access to /proc/{qemu-pid}/mem, which is only available on Linux
        return ()

    try:
        machine_backend = QemuMachine()
    except PermissionError:
        print(
            M.error(
                "Permission error when attempting to parse page tables with gdb-pt-dump.\n"
                "Either change the kernel-vmmap setting, re-run GDB as root, or disable "
                "`ptrace_scope` (`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`)"
            )
        )
        return ()
    except ProcessLookupError:
        print(
            M.error(
                "Could not find the PID for process named `qemu-system`.\n"
                "This might happen if pwndbg is running on a different machine than `qemu-system`,\n"
                "or if the `qemu-system` binary has a different name."
            )
        )
        return ()

    arch = pwndbg.aglib.arch.name
    if arch == "aarch64":
        arch_backend = PT_Aarch64_Backend(machine_backend)
    elif arch == "i386":
        arch_backend = PT_x86_64_Backend(machine_backend)
    elif arch == "x86-64":
        arch_backend = PT_x86_64_Backend(machine_backend)
    elif arch == "rv64":
        arch_backend = PT_RiscV64_Backend(machine_backend)
    else:
        print(
            M.error(
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

    retpages: List[pwndbg.lib.memory.Page] = []
    for page in pages:
        start = page.va
        size = page.page_size
        flags = 4  # IMPLY ALWAYS READ
        if page.pwndbg_is_writeable():
            flags |= 2
        if page.pwndbg_is_executable():
            flags |= 1
        objfile = f"[pt_{hex(start)[2:-3]}]"
        retpages.append(pwndbg.lib.memory.Page(start, size, flags, 0, objfile))
    return tuple(retpages)


monitor_info_mem_not_warned = True


@pwndbg.lib.cache.cache_until("stop")
def kernel_vmmap_via_monitor_info_mem() -> Tuple[pwndbg.lib.memory.Page, ...]:
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
    if not pwndbg.aglib.qemu.is_qemu_kernel():
        return ()

    try:
        monitor_info_mem = pwndbg.dbg.selected_inferior().send_monitor("info mem")
    except pwndbg.dbg_mod.Error:
        # Exception should not happen in new qemu, can we clean up it?
        monitor_info_mem = None

    is_error = monitor_info_mem is None or "unknown command" in monitor_info_mem
    if is_error:
        # Older versions of QEMU/GDB may throw `gdb.error: "monitor" command
        # not supported by this target`. Newer versions will not throw, but will
        # return a string starting with 'unknown command:'. We handle both of
        # these cases in a `finally` block instead of an `except` block.
        # TODO: Find out which other architectures don't support this command
        if pwndbg.aglib.arch.name == "aarch64":
            print(
                M.error(
                    f"The {pwndbg.aglib.arch.name} architecture does"
                    " not support the `monitor info mem` command.\n"
                    "Run `help show kernel-vmmap` for other options."
                )
            )
        return ()

    lines = monitor_info_mem.splitlines()

    # Handle disabled PG
    # This will prevent a crash on abstract architectures
    if len(lines) == 1 and lines[0] == "PG disabled":
        return ()

    global monitor_info_mem_not_warned
    pages: List[pwndbg.lib.memory.Page] = []
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
        if len(perm) == 4:  # if the qemu version displays if the page is executable
            if "x" in perm:
                flags |= 1
        pages.append(pwndbg.lib.memory.Page(start, size, flags, 0, "<qemu>"))

    return tuple(pages)


kernel_vmmap_mode = pwndbg.config.add_param(
    "kernel-vmmap",
    "page-tables",
    "the method to get vmmap information when debugging via QEMU kernel",
    help_docstring="""\
Values explained:

+ `page-tables` - read /proc/$qemu-pid/mem to parse kernel page tables to render vmmap
+ `monitor` - use QEMU's `monitor info mem` to render vmmap
+ `none` - disable vmmap rendering; useful if rendering is particularly slow

Note that the page-tables method will require the QEMU kernel process to be on the same machine and within the same PID namespace. Running QEMU kernel and GDB in different Docker containers will not work. Consider running both containers with --pid=host (meaning they will see and so be able to interact with all processes on the machine).
""",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["page-tables", "monitor", "none"],
)


def kernel_vmmap(process_pages=True) -> Tuple[pwndbg.lib.memory.Page, ...]:
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

    pages = None
    if kernel_vmmap_mode == "page-tables":
        pages = kernel_vmmap_via_page_tables()
    elif kernel_vmmap_mode == "monitor":
        pages = kernel_vmmap_via_monitor_info_mem()
        if process_pages and pwndbg.aglib.arch.name == "x86-64":
            # TODO: check version here when QEMU displays the x bit for x64
            for page in pages:
                pgwalk_res = pwndbg.aglib.kernel.paging.pagewalk(page.start)
                entry, vaddr = pgwalk_res[0]
                if entry and entry >> 63 == 0:
                    page.flags |= 1
    if pages is None:
        return ()
    if process_pages:
        kv = KernelVmmap(pages)
        kv.adjust()

    return tuple(pages)
