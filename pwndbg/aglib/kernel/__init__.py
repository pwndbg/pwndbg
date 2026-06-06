from __future__ import annotations

import functools
import re
from abc import ABC
from abc import abstractmethod
from collections.abc import Callable
from collections.abc import Iterator
from typing import TYPE_CHECKING
from typing import TypeVar

from elftools.elf.elffile import ELFFile
from typing_extensions import ParamSpec

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.structures
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.kernel.structs
import pwndbg.lib.memory
import pwndbg.search
from pwndbg.lib import Status
from pwndbg.lib import TypeNotFoundError
from pwndbg.lib import TypeNotRecoveredError
from pwndbg.lib.regs import BitFlags

if TYPE_CHECKING:
    import pwndbg.aglib.kernel.kconfig_mod
    import pwndbg.aglib.kernel.paging
    import pwndbg.aglib.kernel.slab
    import pwndbg.aglib.kernel.symbol
    import pwndbg.aglib.kernel.vmmap

_kconfig: pwndbg.aglib.kernel.kconfig_mod.Kconfig | None = None

P = ParamSpec("P")
D = TypeVar("D")
T = TypeVar("T")


def BIT(shift: int):
    assert 0 <= shift < 64
    return 1 << shift


def has_debug_symbols(*required: str, checkall: bool = True) -> bool:
    if not required:
        required = ("commit_creds",)
    required_syms_iter = (pwndbg.aglib.symbol.lookup_symbol(sym) is not None for sym in required)
    return all(required_syms_iter) if checkall else any(required_syms_iter)


@pwndbg.lib.cache.cache_until("objfile")
def has_debug_info() -> bool:
    path = pwndbg.aglib.proc.exe()
    if path is None:
        return False
    vmlinux = open(path, "rb")
    elf = ELFFile(vmlinux)
    return any(section.name == ".debug_info" for section in elf.iter_sections())


def requires_debug_symbols(
    *required: str, checkall=False, default: D = None
) -> Callable[[Callable[P, T]], Callable[P, T | D]]:
    def decorator(f: Callable[P, T]) -> Callable[P, T | D]:
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> T | D:
            if has_debug_symbols(*required, checkall=checkall):
                return f(*args, **kwargs)

            # If the user doesn't want an exception thrown when debug symbols are
            # not available, they can instead provide a default return value
            if default is not None:
                return default

            raise Exception(
                f"Function {f.__name__} requires {'all' if checkall else 'any'} of the following symbols: {required}"
            )

        return func

    return decorator


def requires_debug_info(default: D = None) -> Callable[[Callable[P, T]], Callable[P, T | D]]:
    def decorator(f: Callable[P, T]) -> Callable[P, T | D]:
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> T | D:
            if has_debug_info():
                return f(*args, **kwargs)

            # If the user doesn't want an exception thrown when debug symbols are
            # not available, they can instead provide a default return value
            if default is not None:
                return default

            raise Exception(f"Function {f.__name__} requires .debug_info section")

        return func

    return decorator


def typeinfo_recovery(
    name: str, requires_kversion: bool = False, requires_kbase: bool = False
) -> Callable[[Callable[P, str]], Callable[P, None]]:
    """
    Attached to functions which return the C source-code of the `name` type (usually struct).

    Compiles and adds the debug info for the struct into the debugger, from then on accessible via APIs
    like `pwndbg.aglib.memory.get_typed_pointer("struct list_head", db_list)`.
    """

    def decorator(f: Callable[P, str]) -> Callable[P, None]:
        # returns true if the type exists or has been successfully recovered
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> None:
            if not pwndbg.dbg.selected_inferior().is_linux():
                # make sure the target is linux, should we specify symbols instead?
                raise TypeNotRecoveredError(name, "target is not linux")
            if has_debug_info():
                return
            if pwndbg.aglib.typeinfo.lookup_types(name) is not None:
                return
            recover_common_types_func = pwndbg.aglib.kernel.symbol.recover_page_typeinfo
            if f.__name__ != recover_common_types_func.__name__:
                recover_common_types_func()
            if requires_kversion and kversion() is None:
                raise TypeNotRecoveredError(name, "kernel version is unavailable")
            if requires_kbase and kbase() is None:
                raise TypeNotRecoveredError(name, "kernel base not found")

            try:
                result = f(*args, **kwargs)
            except TypeNotFoundError as e:
                raise TypeNotRecoveredError(name, str(e))
            except AssertionError as e:
                # FIXME: Some type recovery functions `assert` under the assumption that the assert
                # will be caught here.
                raise TypeNotRecoveredError(name, str(e))

            fname = name.split()[-1] + "_structs"
            err: Status = pwndbg.aglib.structures.add(fname, result)
            if err.is_failure():
                raise TypeNotRecoveredError(name, err.message)
            return

        return func

    return decorator


@pwndbg.lib.cache.cache_until("start")
def nproc() -> int:
    """Returns the number of processing units available, similar to nproc(1)"""
    return len(pwndbg.dbg.selected_inferior().send_monitor("info cpus").splitlines())


@pwndbg.lib.cache.cache_until("stop")
def first_kernel_ro_page() -> pwndbg.lib.memory.Page | None:
    """Returns the first kernel mapping which contains the linux_banner"""
    base = kbase()
    if base is None:
        return None

    banner = pwndbg.aglib.symbol.lookup_symbol_addr("linux_banner")
    fallback_mappings = []
    for mapping in pwndbg.aglib.kernel.vmmap.kernel_vmmap_pages():
        if mapping.vaddr < base:
            continue
        if banner is not None and banner in mapping:
            return mapping
        if not mapping.read or mapping.write or mapping.execute:
            fallback_mappings.append(mapping)
            continue

        result = next(pwndbg.search.search(b"Linux version", mappings=[mapping]), None)

        if result:
            return mapping
    # optimization: observe that the first Linux kernel region is the kernel text so search it last
    # it now finds the first ro page almost instantly even for kernels that are partially initialized
    # should find it within the first few page chunks if debugging linux kernel (reason for [:10])
    for mapping in fallback_mappings[1:10] + [fallback_mappings[0]]:
        # this loop handles when the kernel has not finished initialization
        # and the permission of the first ro page has not been properly set
        result = next(pwndbg.search.search(b"Linux version", mappings=[mapping]), None)

        if result:
            return mapping

    return None


@pwndbg.lib.cache.cache_until("objfile")
def kconfig() -> pwndbg.aglib.kernel.kconfig_mod.Kconfig:
    global _kconfig
    config_start, config_end = None, None
    if has_debug_symbols():
        config_start = pwndbg.aglib.symbol.lookup_symbol_addr("kernel_config_data")
        config_end = pwndbg.aglib.symbol.lookup_symbol_addr("kernel_config_data_end")
    else:
        mapping = first_kernel_ro_page()
        result = None
        if mapping is not None:
            result = next(pwndbg.search.search(b"IKCFG_ST", mappings=[mapping]), None)

        if result is not None:
            config_start = result + len("IKCFG_ST")
            config_end = next(pwndbg.search.search(b"IKCFG_ED", start=config_start), None)
    if (
        not pwndbg.aglib.memory.is_kernel(config_start)
        or not pwndbg.aglib.memory.is_kernel(config_end)
        or config_start >= config_end
    ):
        _kconfig = pwndbg.aglib.kernel.kconfig_mod.Kconfig(None)
        return _kconfig

    config_size = config_end - config_start

    compressed_config = pwndbg.aglib.memory.read(config_start, config_size)
    _kconfig = pwndbg.aglib.kernel.kconfig_mod.Kconfig(compressed_config)
    return _kconfig


@requires_debug_symbols("saved_command_line", default="")
@pwndbg.lib.cache.cache_until("start")
def kcmdline() -> str:
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("saved_command_line")
    if not addr:
        return ""
    cmdline_addr = pwndbg.aglib.memory.read_pointer_width(addr)
    return pwndbg.aglib.memory.string(cmdline_addr).decode("ascii")


@pwndbg.lib.cache.cache_until("start")
def kversion() -> str | None:
    try:
        if has_debug_symbols("linux_banner"):
            version_addr = pwndbg.aglib.symbol.lookup_symbol_addr("linux_banner")
            result = pwndbg.aglib.memory.string(version_addr).decode("ascii").strip()
            assert len(result) > 0
            return result
    except Exception:
        pass
    mapping = first_kernel_ro_page()
    if mapping is None:
        return None
    version_addr = next(pwndbg.search.search(b"Linux version", mappings=[mapping]), None)
    if version_addr is None:
        return None
    return pwndbg.aglib.memory.string(version_addr).decode("ascii").strip()


@pwndbg.lib.cache.cache_until("start")
def krelease() -> tuple[int, ...] | None:
    _kversion = kversion()
    if _kversion is None:
        return None
    match = re.search(r"Linux version (\d+)\.(\d+)(?:\.(\d+))?", _kversion)
    if match:
        return tuple(int(x) for x in match.groups() if x)
    raise Exception("Linux version tuple not found")


def get_idt_entries() -> Iterator[pwndbg.lib.kernel.structs.IDTEntry]:
    """
    Retrieves the IDT entries from memory.
    """
    base = pwndbg.aglib.regs.idt
    limit = pwndbg.aglib.regs.idt_limit

    size = pwndbg.aglib.arch.ptrsize * 2
    num_entries = (limit + 1) // size

    # TODO: read the entire IDT in one call?
    for i in range(num_entries):
        entry_addr = base + i * size
        entry = pwndbg.lib.kernel.structs.IDTEntry(pwndbg.aglib.memory.read(entry_addr, size))
        yield entry


def current_cpu() -> int:
    return pwndbg.dbg.selected_thread().index() - 1


def get_double_linked_list(head: int, minlen: int = 0x1, maxlen: int = 0x1000) -> list[int] | None:
    # head is a pointer to the double linked list
    # None if not a doubly linked list
    if not pwndbg.aglib.memory.is_kernel(head):
        return None
    nxt = head
    result = []
    for _ in range(maxlen):
        if not pwndbg.aglib.memory.is_kernel(nxt):
            return None
        result.append(nxt)
        nxt = pwndbg.aglib.memory.read_pointer_width(nxt)
        if nxt == result[0]:
            break
    if nxt != result[0]:
        return None
    if len(result) < minlen:
        return None
    for i, nxt in enumerate(result):
        p = pwndbg.aglib.memory.read_pointer_width(nxt + pwndbg.aglib.arch.ptrsize)
        if p != result[i - 1]:
            return None
    return result


def in_kmem_cache(val: int, name: str, strict: bool = True) -> bool:
    # name is a substr of any of the target caches' names
    _, cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(val)
    if not cache:
        return False
    if strict:
        return name == cache.name
    return name in cache.name


class ArchOps(ABC):
    # More information on the physical memory model of the Linux kernel and
    # especially the mapping between pages and page frame numbers (pfn) can
    # be found at https://docs.kernel.org/mm/memory-model.html
    # The provided link also includes guidance on detecting the memory model in
    # use through kernel configuration, enabling support for additional models
    # in the page_to_pfn() and pfn_to_page() methods in the future.

    @abstractmethod
    def per_cpu(
        self, addr: int | pwndbg.dbg_mod.Value, cpu: int | None = None
    ) -> pwndbg.dbg_mod.Value | None:
        raise NotImplementedError()

    @abstractmethod
    def virt_to_phys(self, virt: int) -> int:
        raise NotImplementedError()

    @abstractmethod
    def phys_to_virt(self, phys: int) -> int:
        raise NotImplementedError()

    @abstractmethod
    def phys_to_pfn(self, phys: int) -> int:
        raise NotImplementedError()

    @abstractmethod
    def pfn_to_phys(self, pfn: int) -> int:
        raise NotImplementedError()

    @abstractmethod
    def pfn_to_page(self, pfn: int) -> int:
        raise NotImplementedError()

    @abstractmethod
    def page_to_pfn(self, page: int) -> int:
        raise NotImplementedError()

    def _paginginfo(self) -> pwndbg.aglib.kernel.paging.ArchPagingInfo:
        result = arch_paginginfo()
        if not result:
            raise NotImplementedError()
        return result

    @property
    @pwndbg.lib.cache.cache_until("start")
    def STRUCT_PAGE_SIZE(self):
        return self._paginginfo().STRUCT_PAGE_SIZE

    @property
    @pwndbg.lib.cache.cache_until("start")
    def STRUCT_PAGE_SHIFT(self):
        return self._paginginfo().STRUCT_PAGE_SHIFT

    @property
    def page_offset(self) -> int:
        return self._paginginfo().physmap

    @property
    def ram_phys_start(self) -> int:
        return self._paginginfo().ram_phys_start

    @property
    def page_shift(self) -> int:
        return self._paginginfo().page_shift

    @property
    def vmemmap(self) -> int:
        return self._paginginfo().vmemmap

    @property
    def kbase(self) -> int | None:
        return self._paginginfo().kbase

    @property
    def vmalloc(self) -> int:
        return self._paginginfo().vmalloc

    @property
    def page_size(self) -> int:
        return self._paginginfo().page_size

    def virt_to_pfn(self, virt: int) -> int:
        return phys_to_pfn(virt_to_phys(virt))

    def pfn_to_virt(self, pfn: int) -> int:
        return phys_to_virt(pfn_to_phys(pfn))

    def phys_to_page(self, phys: int) -> int:
        return pfn_to_page(phys_to_pfn(phys))

    def page_to_phys(self, page: int) -> int:
        return pfn_to_phys(page_to_pfn(page))

    def virt_to_page(self, virt: int) -> int:
        return pfn_to_page(virt_to_pfn(virt))

    def page_to_virt(self, page: int) -> int:
        return pfn_to_virt(page_to_pfn(page))


class x86Ops(ArchOps):
    def phys_to_virt(self, phys: int) -> int:
        return pwndbg.aglib.arch.unsigned(phys + self.page_offset)

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.page_shift

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.page_shift

    @staticmethod
    def paging_enabled() -> bool:
        return int(pwndbg.aglib.regs.read_reg("cr0")) & BIT(31) != 0


class i386Ops(x86Ops):
    def virt_to_phys(self, virt: int) -> int:
        return (virt - self.page_offset) % (1 << 32)

    def per_cpu(
        self, addr: int | pwndbg.dbg_mod.Value, cpu: int | None = None
    ) -> pwndbg.dbg_mod.Value:
        raise NotImplementedError()

    def pfn_to_page(self, pfn: int) -> int:
        raise NotImplementedError()

    def page_to_pfn(self, page: int) -> int:
        raise NotImplementedError()


class x86_64Ops(x86Ops):
    def __init__(self) -> None:
        self.phys_base = 0x1000000

    @requires_debug_symbols("__per_cpu_offset", "nr_iowait_cpu", checkall=False)
    def per_cpu(
        self, addr: int | pwndbg.dbg_mod.Value, cpu: int | None = None
    ) -> pwndbg.dbg_mod.Value | None:
        if cpu is None:
            cpu = current_cpu()

        per_cpu_offset = pwndbg.aglib.kernel.per_cpu_offset()
        if per_cpu_offset is None:
            return None

        offset = pwndbg.aglib.memory.read_pointer_width(per_cpu_offset + (cpu * 8))
        per_cpu_addr = (int(addr) + offset) % 2**64
        if isinstance(addr, pwndbg.dbg_mod.Value):
            return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr, addr.type)
        return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr)

    def virt_to_phys(self, virt: int) -> int:
        _virt: int | None = virt
        if not (pwndbg.aglib.memory.is_kernel(virt) and virt < self.vmalloc):
            # if not within physmap range, first find the physmap address
            _virt = pagewalk(virt).virt
        if _virt is None:
            _virt = virt
        return _virt - self.page_offset

    def pfn_to_page(self, pfn: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (pfn << self.STRUCT_PAGE_SHIFT) + self.vmemmap

    def page_to_pfn(self, page: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (page - self.vmemmap) >> self.STRUCT_PAGE_SHIFT


class Aarch64Ops(ArchOps):
    @requires_debug_symbols("__per_cpu_offset", "nr_iowait_cpu", checkall=False)
    def per_cpu(
        self, addr: int | pwndbg.dbg_mod.Value, cpu: int | None = None
    ) -> pwndbg.dbg_mod.Value | None:
        if cpu is None:
            cpu = current_cpu()

        per_cpu_offset = pwndbg.aglib.kernel.per_cpu_offset()
        if per_cpu_offset is None:
            return None

        offset = pwndbg.aglib.memory.u(per_cpu_offset + (cpu * 8))
        per_cpu_addr = (int(addr) + offset) % 2**64
        if isinstance(addr, pwndbg.dbg_mod.Value):
            return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr, addr.type)
        return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr)

    def virt_to_phys(self, virt: int) -> int:
        _virt: int | None = virt
        if not (pwndbg.aglib.memory.is_kernel(virt) and virt < self.vmalloc):
            # if not within physmap range, first find the physmap address
            _virt = pagewalk(virt).virt
        if _virt is None:
            _virt = virt
        return _virt - self.page_offset + self.ram_phys_start

    def phys_to_virt(self, phys: int) -> int:
        # https://elixir.bootlin.com/linux/v6.16.4/source/arch/arm64/include/asm/memory.h#L356
        return phys - self.ram_phys_start + self.page_offset

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.page_shift

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.page_shift

    def pfn_to_page(self, pfn: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (pfn << self.STRUCT_PAGE_SHIFT) + self.vmemmap

    def page_to_pfn(self, page: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (page - self.vmemmap) >> self.STRUCT_PAGE_SHIFT

    @staticmethod
    def paging_enabled() -> bool:
        # AArch64 system control register: newer QEMU releases (tested on
        # 10.2.0) expose it as `SCTLR_EL1`; older releases used the generic
        # `SCTLR`. Bit 0 (M) is the MMU-enable flag in either case. See
        # #3871 / #3875.
        return int(pwndbg.aglib.regs.read_reg("SCTLR_EL1", "SCTLR")) & BIT(0) != 0


@pwndbg.lib.cache.cache_until("start")
def arch_paginginfo() -> pwndbg.aglib.kernel.paging.ArchPagingInfo | None:
    if pwndbg.aglib.arch.name == "aarch64":
        return pwndbg.aglib.kernel.paging.Aarch64PagingInfo()
    if pwndbg.aglib.arch.name == "x86-64":
        return pwndbg.aglib.kernel.paging.x86_64PagingInfo()
    return None


@pwndbg.lib.cache.cache_until("start")
def arch_ops() -> ArchOps | None:
    if pwndbg.aglib.arch.name == "aarch64":
        return Aarch64Ops()
    if pwndbg.aglib.arch.name == "x86-64":
        return x86_64Ops()
    if pwndbg.aglib.arch.name == "i386":
        return i386Ops()
    return None


@pwndbg.lib.cache.cache_until("start")
def arch_symbols() -> pwndbg.aglib.kernel.symbol.ArchSymbols | None:
    if pwndbg.aglib.arch.name == "aarch64":
        return pwndbg.aglib.kernel.symbol.Aarch64Symbols()
    if pwndbg.aglib.arch.name == "x86-64":
        return pwndbg.aglib.kernel.symbol.x86_64Symbols()
    return None


def page_size() -> int:
    ops = arch_ops()
    if ops:
        return ops.page_size
    raise NotImplementedError()


def per_cpu(addr: int | pwndbg.dbg_mod.Value, cpu: int | None = None) -> pwndbg.dbg_mod.Value:
    ops = arch_ops()
    if ops:
        return ops.per_cpu(addr, cpu)
    raise NotImplementedError()


def virt_to_phys(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_phys(virt)
    raise NotImplementedError()


def phys_to_virt(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_virt(phys)
    raise NotImplementedError()


def phys_to_pfn(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_pfn(phys)
    raise NotImplementedError()


def pfn_to_phys(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_phys(pfn)
    raise NotImplementedError()


def pfn_to_page(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_page(pfn)
    raise NotImplementedError()


def page_to_pfn(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_pfn(page)
    raise NotImplementedError()


def phys_to_page(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_page(phys)
    raise NotImplementedError()


def page_to_phys(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_phys(page)
    raise NotImplementedError()


def virt_to_page(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_page(virt)
    raise NotImplementedError()


def page_to_virt(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_virt(page)
    raise NotImplementedError()


def pfn_to_virt(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_virt(pfn)
    raise NotImplementedError()


def virt_to_pfn(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_pfn(virt)
    raise NotImplementedError()


@pwndbg.lib.cache.cache_until("stop")
def kbase() -> int | None:
    ops = arch_ops()
    if ops:
        return ops.kbase
    raise NotImplementedError()


@pwndbg.lib.cache.cache_until("stop")
def page_shift() -> int:
    ops = arch_ops()
    if ops:
        return ops.page_shift
    raise NotImplementedError()


@pwndbg.lib.cache.cache_until("stop")
def pagewalk(
    addr, entry: int | None = None, virt: bool = True
) -> pwndbg.aglib.kernel.paging.PagewalkResult:
    """
    assumes entry is a valid physaddr (+ flags)
    the strategy is to walk any virtual pgd first
    """
    pi = arch_paginginfo()
    if pi:
        return pi.pagewalk(addr, entry, virt)
    raise NotImplementedError()


@pwndbg.lib.cache.cache_until("stop")
def pagescan(entry=None) -> tuple[pwndbg.lib.memory.Page, ...]:
    pi = arch_paginginfo()
    if pi:
        return tuple(pi.pagescan(entry))
    raise NotImplementedError()


def bitflags(level: pwndbg.aglib.kernel.paging.PageTableLevel) -> BitFlags:
    pi = arch_paginginfo()
    if pi:
        return pi.bitflags(level)
    raise NotImplementedError()


def PAGE_ENTRY_MASK() -> int:
    pi = arch_paginginfo()
    if pi:
        return pi.PAGE_ENTRY_MASK
    raise NotImplementedError()


def STRUCT_PAGE_SIZE() -> int:
    pi = arch_paginginfo()
    if pi:
        return pi.STRUCT_PAGE_SIZE
    raise NotImplementedError()


def slab_to_virt(slab: int) -> int:
    pi = arch_paginginfo()
    if pi:
        return pi.slab_to_virt(slab)
    raise NotImplementedError()


def virt_to_slab(slab: int) -> int:
    pi = arch_paginginfo()
    if pi:
        return pi.virt_to_slab(slab)
    raise NotImplementedError()


def slab_virtual() -> int:
    pi = arch_paginginfo()
    if pi:
        return pi.slab_virtual
    raise NotImplementedError()


def paging_enabled() -> bool:
    arch_name = pwndbg.aglib.arch.name
    if arch_name == "i386":
        return i386Ops.paging_enabled()
    if arch_name == "x86-64":
        return x86_64Ops.paging_enabled()
    if arch_name == "aarch64":
        return Aarch64Ops.paging_enabled()
    if arch_name == "rv64":
        # https://starfivetech.com/uploads/u74_core_complex_manual_21G1.pdf
        # page 41, satp.MODE, bits: 60,61,62,63
        # "When satp.MODE=0x0, supervisor virtual addresses are equal to supervisor physical addresses"
        return (
            int(pwndbg.aglib.regs.read_reg("satp")) & (BIT(60) | BIT(61) | BIT(62) | BIT(63)) != 0
        )
    raise NotImplementedError()


@requires_debug_symbols("node_states", default=1)
def num_numa_nodes() -> int:
    """Returns the number of NUMA nodes that are online on the system"""
    kc = kconfig()

    if "CONFIG_NUMA" not in kc:
        return 1

    if "CONFIG_NODES_SHIFT" not in kc:
        node_states = pwndbg.aglib.symbol.lookup_symbol("node_states")
        if node_states is None or not has_debug_info():
            return 1
        node_states = node_states.dereference()

        # 1 means aglib.typeinfo.enum_member("enum node_states", "N_ONLINE")
        node_mask = node_states[1]["bits"][0]
        return int(node_mask).bit_count()

    max_nodes = 1 << int(kc["CONFIG_NODES_SHIFT"])
    if max_nodes == 1:
        return 1

    val = pwndbg.aglib.kernel.symbol.try_usymbol("nr_online_nodes", 32)
    if val is None:
        return 1

    return val


@pwndbg.lib.cache.cache_until("stop")
def node_data() -> int | None:
    if (syms := arch_symbols()) is not None:
        return syms.node_data()
    return None


@pwndbg.lib.cache.cache_until("stop")
def slab_caches() -> pwndbg.dbg_mod.Value | None:
    if (syms := arch_symbols()) is not None:
        if addr := syms.slab_caches():
            return pwndbg.aglib.memory.get_typed_pointer_value("struct list_head", addr)
    return None


@pwndbg.lib.cache.cache_until("stop")
def per_cpu_offset() -> int | None:
    if (syms := arch_symbols()) is not None:
        return syms.per_cpu_offset()
    return None


@pwndbg.lib.cache.cache_until("stop")
def modules() -> int | None:
    if (syms := arch_symbols()) is not None:
        return syms.modules()
    return None


@pwndbg.lib.cache.cache_until("stop")
def db_list() -> int | None:
    if (syms := arch_symbols()) is not None:
        return syms.db_list()
    return None


@pwndbg.lib.cache.cache_until("stop")
def prog_idr() -> int | None:
    if (syms := arch_symbols()) is not None:
        return syms.prog_idr()
    return None


@pwndbg.lib.cache.cache_until("stop")
def map_idr() -> int | None:
    if (syms := arch_symbols()) is not None:
        return syms.map_idr()
    return None


@pwndbg.lib.cache.cache_until("stop")
def current_task(cpu: int | None = None) -> int | None:
    if (syms := arch_symbols()) is not None:
        result = syms.current_task()
        if not isinstance(result, int):
            return None
        if pwndbg.aglib.arch.name == "aarch64":
            # TODO: how to get the kcurrent for different cpus
            return result
        ptr = int(per_cpu(result, cpu=cpu))
        return pwndbg.aglib.memory.read_pointer_width(ptr)
    return None


@pwndbg.lib.cache.cache_until("stop")
def init_task() -> int | None:
    if (syms := arch_symbols()) is not None:
        return syms.init_task()
    return None
