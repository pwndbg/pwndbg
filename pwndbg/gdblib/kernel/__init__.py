from __future__ import annotations

import functools
import math
import re
from abc import ABC
from abc import abstractmethod
from typing import Callable
from typing import List
from typing import Tuple
from typing import TypeVar

import gdb
from typing_extensions import ParamSpec

import pwndbg.color.message as M
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol
import pwndbg.lib.cache
import pwndbg.lib.kernel.kconfig
import pwndbg.lib.kernel.structs
import pwndbg.search

_kconfig: pwndbg.lib.kernel.kconfig.Kconfig | None = None

P = ParamSpec("P")
D = TypeVar("D")
T = TypeVar("T")


def BIT(shift: int):
    assert 0 <= shift < 64
    return 1 << shift


@pwndbg.lib.cache.cache_until("objfile")
def has_debug_syms() -> bool:
    # Check for an arbitrary type and symbol name that are not likely to change
    return (
        pwndbg.gdblib.typeinfo.load("struct file") is not None
        and pwndbg.gdblib.symbol.address("linux_banner") is not None
    )


# NOTE: This implies requires_debug_syms(), as it is needed for kconfig() to return non-None
def requires_kconfig(default: D = None) -> Callable[[Callable[P, T]], Callable[P, T | D]]:
    def decorator(f: Callable[P, T]) -> Callable[P, T | D]:
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> T | D:
            if kconfig():
                return f(*args, **kwargs)

            # If the user doesn't want an exception thrown when CONFIG_IKCONFIG is
            # not enabled, they can instead provide a default return value
            if default is not None:
                return default

            raise Exception(f"Function {f.__name__} requires CONFIG_IKCONFIG enabled in kernel")

        return func

    return decorator


def requires_debug_syms(default: D = None) -> Callable[[Callable[P, T]], Callable[P, T | D]]:
    def decorator(f: Callable[P, T]) -> Callable[P, T | D]:
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> T | D:
            if has_debug_syms():
                return f(*args, **kwargs)

            # If the user doesn't want an exception thrown when debug symbols are
            # not available, they can instead provide a default return value
            if default is not None:
                return default

            raise Exception(f"Function {f.__name__} requires debug symbols")

        return func

    return decorator


@requires_debug_syms(default=1)
def nproc() -> int:
    """Returns the number of processing units available, similar to nproc(1)"""
    return int(gdb.lookup_global_symbol("nr_cpu_ids").value())


def get_first_kernel_ro():
    """Returns the first kernel mapping which contains the linux_banner"""
    base = kbase()

    for mapping in pwndbg.gdblib.vmmap.get():
        if mapping.vaddr < base:
            continue

        results = list(pwndbg.search.search(b"Linux version", mappings=[mapping]))

        if len(results) > 0:
            return mapping

    return None


def load_kconfig() -> pwndbg.lib.kernel.kconfig.Kconfig | None:
    if has_debug_syms():
        config_start = pwndbg.gdblib.symbol.address("kernel_config_data")
        config_end = pwndbg.gdblib.symbol.address("kernel_config_data_end")
    else:
        mapping = get_first_kernel_ro()
        results = list(pwndbg.search.search(b"IKCFG_ST", mappings=[mapping]))

        if len(results) == 0:
            return None

        config_start = results[0] + len("IKCFG_ST")
        config_end = list(pwndbg.search.search(b"IKCFG_ED", start=config_start))[0]

    if config_start is None or config_end is None:
        return None

    config_size = config_end - config_start

    compressed_config = pwndbg.gdblib.memory.read(config_start, config_size)
    return pwndbg.lib.kernel.kconfig.Kconfig(compressed_config)


@pwndbg.lib.cache.cache_until("start")
def kconfig() -> pwndbg.lib.kernel.kconfig.Kconfig | None:
    global _kconfig
    if _kconfig is None:
        _kconfig = load_kconfig()
    elif len(_kconfig) == 0:
        return None
    return _kconfig


@requires_debug_syms(default="")
@pwndbg.lib.cache.cache_until("start")
def kcmdline() -> str:
    cmdline_addr = pwndbg.gdblib.memory.pvoid(pwndbg.gdblib.symbol.address("saved_command_line"))
    return pwndbg.gdblib.memory.string(cmdline_addr).decode("ascii")


@pwndbg.lib.cache.cache_until("start")
def kversion() -> str:
    if has_debug_syms():
        version_addr = pwndbg.gdblib.symbol.address("linux_banner")
    else:
        mapping = get_first_kernel_ro()
        version_addr = list(pwndbg.search.search(b"Linux version", mappings=[mapping]))[0]

    return pwndbg.gdblib.memory.string(version_addr).decode("ascii").strip()


@pwndbg.lib.cache.cache_until("start")
def krelease() -> Tuple[int, ...]:
    match = re.search(r"Linux version (\d+)\.(\d+)(?:\.(\d+))?", kversion())
    if match:
        return tuple(int(x) for x in match.groups() if x)
    raise Exception("Linux version tuple not found")


@requires_kconfig()
@pwndbg.lib.cache.cache_until("start")
def is_kaslr_enabled() -> bool:
    if "CONFIG_RANDOMIZE_BASE" not in kconfig():
        return False

    return "nokaslr" not in kcmdline()


@pwndbg.lib.cache.cache_until("start")
def kbase() -> int | None:
    arch_name = pwndbg.gdblib.arch.name

    address = 0

    if arch_name == "x86-64":
        address = get_idt_entries()[0].offset
    elif arch_name == "aarch64":
        address = pwndbg.gdblib.regs.vbar
    else:
        return None

    mappings = pwndbg.gdblib.vmmap.get()
    for mapping in mappings:
        # TODO: Check alignment

        # only search in kernel mappings:
        # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
        if mapping.vaddr & (0xFFFF << 48) == 0:
            continue

        if not mapping.execute:
            continue

        if address in mapping:
            return mapping.vaddr

    return None


def get_idt_entries() -> List[pwndbg.lib.kernel.structs.IDTEntry]:
    """
    Retrieves the IDT entries from memory.
    """
    base = pwndbg.gdblib.regs.idt
    limit = pwndbg.gdblib.regs.idt_limit

    size = pwndbg.gdblib.arch.ptrsize * 2
    num_entries = (limit + 1) // size

    entries = []

    # TODO: read the entire IDT in one call?
    for i in range(num_entries):
        entry_addr = base + i * size
        entry = pwndbg.lib.kernel.structs.IDTEntry(pwndbg.gdblib.memory.read(entry_addr, size))
        entries.append(entry)

    return entries


class ArchOps(ABC):
    # More information on the physical memory model of the Linux kernel and
    # especially the mapping between pages and page frame numbers (pfn) can
    # be found at https://docs.kernel.org/mm/memory-model.html
    # The provided link also includes guidance on detecting the memory model in
    # use through kernel configuration, enabling support for additional models
    # in the page_to_pfn() and pfn_to_page() methods in the future.

    @abstractmethod
    def page_size(self) -> int:
        raise NotImplementedError()

    @abstractmethod
    def per_cpu(self, addr: gdb.Value, cpu=None):
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
    def pfn_to_page(self, phys: int) -> int:
        raise NotImplementedError()

    @abstractmethod
    def page_to_pfn(self, page: int) -> int:
        raise NotImplementedError()

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
    def page_size(self) -> int:
        return 1 << self.page_shift

    def phys_to_virt(self, phys: int) -> int:
        return (phys + self.page_offset) % (1 << self.ptr_size)

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.page_shift

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.page_shift

    @property
    @abstractmethod
    def ptr_size(self) -> int:
        raise NotImplementedError()

    @property
    @abstractmethod
    def page_shift(self) -> int:
        raise NotImplementedError()

    @property
    @abstractmethod
    def page_offset(self) -> int:
        raise NotImplementedError()

    @staticmethod
    def paging_enabled() -> bool:
        return int(pwndbg.gdblib.regs.cr0) & BIT(31) != 0


class i386Ops(x86Ops):
    @requires_kconfig()
    def __init__(self) -> None:
        # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_32_types.h#L18
        self._PAGE_OFFSET = int(kconfig()["CONFIG_PAGE_OFFSET"], 16)
        self.START_KERNEL_map = self._PAGE_OFFSET

    @property
    def ptr_size(self) -> int:
        return 32

    @property
    def page_offset(self) -> int:
        return self._PAGE_OFFSET

    @property
    def page_shift(self) -> int:
        # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_types.h#L10
        return 12

    def virt_to_phys(self, virt: int) -> int:
        return (virt - self.page_offset) % (1 << 32)

    def per_cpu(self, addr: gdb.Value, cpu: int | None = None):
        raise NotImplementedError()

    def pfn_to_page(self, pfn: int) -> int:
        raise NotImplementedError()

    def page_to_pfn(self, page: int) -> int:
        raise NotImplementedError()


class x86_64Ops(x86Ops):
    def __init__(self) -> None:
        if self.uses_5lvl_paging():
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L41
            self._PAGE_OFFSET = 0xFF11000000000000
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/pgtable_64_types.h#L131
            self.VMEMMAP_START = 0xFFD4000000000000
        else:
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L42
            self._PAGE_OFFSET = 0xFFFF888000000000
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/pgtable_64_types.h#L130
            self.VMEMMAP_START = 0xFFFFEA0000000000

        self.STRUCT_PAGE_SIZE = gdb.lookup_type("struct page").sizeof
        self.STRUCT_PAGE_SHIFT = int(math.log2(self.STRUCT_PAGE_SIZE))

        self.START_KERNEL_map = 0xFFFFFFFF80000000
        self.phys_base = 0x1000000

    @property
    def ptr_size(self) -> int:
        return 64

    @property
    def page_offset(self) -> int:
        return self._PAGE_OFFSET

    @property
    def page_shift(self) -> int:
        # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L50
        return 12

    @requires_debug_syms()
    def per_cpu(self, addr: gdb.Value, cpu: int | None = None):
        if cpu is None:
            cpu = gdb.selected_thread().num - 1

        per_cpu_offset = pwndbg.gdblib.symbol.address("__per_cpu_offset")
        offset = pwndbg.gdblib.memory.u(per_cpu_offset + (cpu * 8))
        per_cpu_addr = (int(addr) + offset) % 2**64
        return gdb.Value(per_cpu_addr).cast(addr.type)

    def virt_to_phys(self, virt: int) -> int:
        if virt < self.START_KERNEL_map:
            return (virt - self.page_offset) % (1 << 64)
        return ((virt - self.START_KERNEL_map) + self.phys_base) % (1 << 64)

    def pfn_to_page(self, pfn: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (pfn << self.STRUCT_PAGE_SHIFT) + self.VMEMMAP_START

    def page_to_pfn(self, page: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (page - self.VMEMMAP_START) >> self.STRUCT_PAGE_SHIFT

    @staticmethod
    @requires_debug_syms()
    def cpu_feature_capability(feature: int) -> bool:
        boot_cpu_data = gdb.lookup_global_symbol("boot_cpu_data").value()
        capabilities = boot_cpu_data["x86_capability"]
        return (int(capabilities[feature // 32]) >> (feature % 32)) & 1 == 1

    @staticmethod
    @requires_debug_syms()
    def uses_5lvl_paging() -> bool:
        # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/cpufeatures.h#L381
        X86_FEATURE_LA57 = 16 * 32 + 16
        # Separate to avoid using kconfig if possible
        if not x86_64Ops.cpu_feature_capability(X86_FEATURE_LA57) or "no5lvl" in kcmdline():
            return False
        return x86_64Ops._kconfig_5lvl_paging()

    @staticmethod
    @requires_kconfig()
    def _kconfig_5lvl_paging() -> bool:
        return kconfig().get("CONFIG_X86_5LEVEL") == "y"


class Aarch64Ops(ArchOps):
    @requires_kconfig(default={})
    def __init__(self) -> None:
        self.STRUCT_PAGE_SIZE = gdb.lookup_type("struct page").sizeof
        self.STRUCT_PAGE_SHIFT = int(math.log2(self.STRUCT_PAGE_SIZE))

        self.VA_BITS = int(kconfig()["ARM64_VA_BITS"])
        self.PAGE_SHIFT = int(kconfig()["CONFIG_ARM64_PAGE_SHIFT"])

        self.PHYS_OFFSET = pwndbg.gdblib.memory.u(pwndbg.gdblib.symbol.address("memstart_addr"))
        self.PAGE_OFFSET = (-1 << self.VA_BITS) + 2**64

        VA_BITS_MIN = 48 if self.VA_BITS > 48 else self.VA_BITS
        PAGE_END = (-1 << (VA_BITS_MIN - 1)) + 2**64
        VMEMMAP_SIZE = (PAGE_END - self.PAGE_OFFSET) >> (self.PAGE_SHIFT - self.STRUCT_PAGE_SHIFT)

        if pwndbg.gdblib.kernel.krelease() >= (5, 11):
            # Linux 5.11 changed the calculation for VMEMMAP_START
            # https://elixir.bootlin.com/linux/v5.11/source/arch/arm64/include/asm/memory.h#L53
            self.VMEMMAP_SHIFT = self.PAGE_SHIFT - self.STRUCT_PAGE_SHIFT
            self.VMEMMAP_START = -(1 << (self.VA_BITS - self.VMEMMAP_SHIFT)) % (1 << 64)
        else:
            self.VMEMMAP_START = (-VMEMMAP_SIZE - 2 * 1024 * 1024) + 2**64

    def page_size(self) -> int:
        return 1 << self.PAGE_SHIFT

    @requires_debug_syms()
    def per_cpu(self, addr: gdb.Value, cpu: int | None = None):
        if cpu is None:
            cpu = gdb.selected_thread().num - 1

        per_cpu_offset = pwndbg.gdblib.symbol.address("__per_cpu_offset")
        offset = pwndbg.gdblib.memory.u(per_cpu_offset + (cpu * 8))
        per_cpu_addr = (int(addr) + offset) % 2**64
        return gdb.Value(per_cpu_addr).cast(addr.type)

    def virt_to_phys(self, virt: int) -> int:
        return virt - self.PAGE_OFFSET

    def phys_to_virt(self, phys: int) -> int:
        return phys + self.PAGE_OFFSET

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.PAGE_SHIFT

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.PAGE_SHIFT

    def pfn_to_page(self, pfn: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (pfn << self.STRUCT_PAGE_SHIFT) + self.VMEMMAP_START

    def page_to_pfn(self, page: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (page - self.VMEMMAP_START) >> self.STRUCT_PAGE_SHIFT

    @staticmethod
    def paging_enabled() -> bool:
        return int(pwndbg.gdblib.regs.SCTLR) & BIT(0) != 0


_arch_ops: ArchOps = None


@pwndbg.lib.cache.cache_until("start")
def arch_ops() -> ArchOps:
    global _arch_ops
    if _arch_ops is None:
        if pwndbg.gdblib.arch.name == "aarch64":
            _arch_ops = Aarch64Ops()
        elif pwndbg.gdblib.arch.name == "x86-64":
            _arch_ops = x86_64Ops()
        elif pwndbg.gdblib.arch.name == "i386":
            _arch_ops = i386Ops()

    return _arch_ops


def page_size() -> int:
    ops = arch_ops()
    if ops:
        return ops.page_size()
    else:
        raise NotImplementedError()


def per_cpu(addr: gdb.Value, cpu: int | None = None):
    ops = arch_ops()
    if ops:
        return ops.per_cpu(addr, cpu)
    else:
        raise NotImplementedError()


def virt_to_phys(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_phys(virt)
    else:
        raise NotImplementedError()


def phys_to_virt(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_virt(phys)
    else:
        raise NotImplementedError()


def phys_to_pfn(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_pfn(phys)
    else:
        raise NotImplementedError()


def pfn_to_phys(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_phys(pfn)
    else:
        raise NotImplementedError()


def pfn_to_page(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_page(pfn)
    else:
        raise NotImplementedError()


def page_to_pfn(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_pfn(page)
    else:
        raise NotImplementedError()


def phys_to_page(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_page(phys)
    else:
        raise NotImplementedError()


def page_to_phys(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_phys(page)
    else:
        raise NotImplementedError()


def virt_to_page(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_page(virt)
    else:
        raise NotImplementedError()


def page_to_virt(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_virt(page)
    else:
        raise NotImplementedError()


def pfn_to_virt(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_virt(pfn)
    else:
        raise NotImplementedError()


def virt_to_pfn(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_pfn(virt)
    else:
        raise NotImplementedError()


def paging_enabled() -> bool:
    arch_name = pwndbg.gdblib.arch.name
    if arch_name == "i386":
        return i386Ops.paging_enabled()
    elif arch_name == "x86-64":
        return x86_64Ops.paging_enabled()
    elif arch_name == "aarch64":
        return Aarch64Ops.paging_enabled()
    else:
        raise NotImplementedError()


@requires_debug_syms()
def num_numa_nodes() -> int:
    """Returns the number of NUMA nodes that are online on the system"""
    kc = kconfig()
    if kc is None:
        # if no config, we can still try one other way
        node_states = gdb.lookup_global_symbol("node_states")
        if node_states is None:
            return 1
        node_states = gdb.lookup_global_symbol("node_states").value()
        node_mask = node_states[1]["bits"][0]  # 1 means N_ONLINE
        return bin(node_mask).count("1")

    if "CONFIG_NUMA" not in kc:
        return 1

    max_nodes = 1 << int(kc["CONFIG_NODES_SHIFT"])
    if max_nodes == 1:
        return 1

    return int(gdb.lookup_global_symbol("nr_online_nodes").value())
