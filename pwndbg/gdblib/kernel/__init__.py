import functools
import math
import re
from typing import Optional
from typing import Tuple

import gdb

import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.lib.cache
import pwndbg.lib.kernel.kconfig

_kconfig: pwndbg.lib.kernel.kconfig.Kconfig = None


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


def requires_debug_syms(default=None):
    def decorator(f):
        @functools.wraps(f)
        def func(*args, **kwargs):
            if has_debug_syms():
                return f(*args, **kwargs)

            # If the user doesn't want an exception thrown when debug symbols are
            # not available, they can instead provide a default return value
            if default is not None:
                return default

            raise Exception(f"Function {f.__name__} requires CONFIG_IKCONFIG")

        return func

    return decorator


@requires_debug_syms(default=1)
def nproc() -> int:
    """Returns the number of processing units available, similar to nproc(1)"""
    return int(gdb.lookup_global_symbol("nr_cpu_ids").value())


@requires_debug_syms(default={})
def load_kconfig() -> pwndbg.lib.kernel.kconfig.Kconfig:
    config_start = pwndbg.gdblib.symbol.address("kernel_config_data")
    config_end = pwndbg.gdblib.symbol.address("kernel_config_data_end")
    config_size = config_end - config_start

    compressed_config = pwndbg.gdblib.memory.read(config_start, config_size)
    return pwndbg.lib.kernel.kconfig.Kconfig(compressed_config)


@pwndbg.lib.cache.cache_until("start")
def kconfig() -> pwndbg.lib.kernel.kconfig.Kconfig:
    global _kconfig
    if _kconfig is None:
        _kconfig = load_kconfig()
    return _kconfig


@requires_debug_syms(default="")
@pwndbg.lib.cache.cache_until("start")
def kcmdline() -> str:
    cmdline_addr = pwndbg.gdblib.memory.pvoid(pwndbg.gdblib.symbol.address("saved_command_line"))
    return pwndbg.gdblib.memory.string(cmdline_addr).decode("ascii")


@requires_debug_syms(default="")
@pwndbg.lib.cache.cache_until("start")
def kversion() -> str:
    version_addr = pwndbg.gdblib.symbol.address("linux_banner")
    return pwndbg.gdblib.memory.string(version_addr).decode("ascii").strip()


@requires_debug_syms()
@pwndbg.lib.cache.cache_until("start")
def krelease() -> Tuple[int, ...]:
    match = re.search(r"Linux version (\d+)\.(\d+)(?:\.(\d+))?", kversion())
    if match:
        return tuple(int(x) for x in match.groups() if x)
    raise Exception("Linux version tuple not found")


@requires_debug_syms()
@pwndbg.lib.cache.cache_until("start")
def is_kaslr_enabled() -> bool:
    if "CONFIG_RANDOMIZE_BASE" not in kconfig():
        return False

    return "nokaslr" not in kcmdline()


class ArchOps:
    # More information on the physical memory model of the Linux kernel and
    # especially the mapping between pages and page frame numbers (pfn) can
    # be found at https://docs.kernel.org/mm/memory-model.html
    # The provided link also includes guidance on detecting the memory model in
    # use through kernel configuration, enabling support for additional models
    # in the page_to_pfn() and pfn_to_page() methods in the future.

    def page_size(self) -> int:
        raise NotImplementedError()

    def per_cpu(self, addr: gdb.Value, cpu=None):
        raise NotImplementedError()

    def virt_to_phys(self, virt: int) -> int:
        raise NotImplementedError()

    def phys_to_virt(self, phys: int) -> int:
        raise NotImplementedError()

    def phys_to_pfn(self, phys: int) -> int:
        raise NotImplementedError()

    def pfn_to_phys(self, pfn: int) -> int:
        raise NotImplementedError()

    def pfn_to_page(self, phys: int) -> int:
        raise NotImplementedError()

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


class x86_64Ops(ArchOps):
    def __init__(self) -> None:
        if self.uses_5lvl_paging():
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L41
            self.PAGE_OFFSET = 0xFF11000000000000
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/pgtable_64_types.h#L131
            self.VMEMMAP_START = 0xFFD4000000000000
        else:
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L42
            self.PAGE_OFFSET = 0xFFFF888000000000
            # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/pgtable_64_types.h#L130
            self.VMEMMAP_START = 0xFFFFEA0000000000

        self.STRUCT_PAGE_SIZE = gdb.lookup_type("struct page").sizeof
        self.STRUCT_PAGE_SHIFT = int(math.log2(self.STRUCT_PAGE_SIZE))

        # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L50
        self.START_KERNEL_map = 0xFFFFFFFF80000000
        self.PAGE_SHIFT = 12
        self.phys_base = 0x1000000

    def page_size(self) -> int:
        return 1 << self.PAGE_SHIFT

    def per_cpu(self, addr: gdb.Value, cpu: Optional[int] = None):
        if cpu is None:
            cpu = gdb.selected_thread().num - 1

        per_cpu_offset = pwndbg.gdblib.symbol.address("__per_cpu_offset")
        offset = pwndbg.gdblib.memory.u(per_cpu_offset + (cpu * 8))
        per_cpu_addr = (int(addr) + offset) % 2**64
        return gdb.Value(per_cpu_addr).cast(addr.type)

    def virt_to_phys(self, virt: int) -> int:
        if virt < self.START_KERNEL_map:
            return (virt - self.PAGE_OFFSET) % (1 << 64)
        return ((virt - self.START_KERNEL_map) + self.phys_base) % (1 << 64)

    def phys_to_virt(self, phys: int) -> int:
        return (phys + self.PAGE_OFFSET) % (1 << 64)

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
        return int(pwndbg.gdblib.regs.cr0) & BIT(31) != 0

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
        return (
            kconfig().get("CONFIG_X86_5LEVEL") == "y"
            and "no5lvl" not in kcmdline()
            and x86_64Ops.cpu_feature_capability(X86_FEATURE_LA57)
        )


class Aarch64Ops(ArchOps):
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

    def per_cpu(self, addr: gdb.Value, cpu: Optional[int] = None):
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


@requires_debug_syms(default={})
@pwndbg.lib.cache.cache_until("start")
def arch_ops() -> ArchOps:
    global _arch_ops
    if _arch_ops is None:
        if pwndbg.gdblib.arch.name == "aarch64":
            _arch_ops = Aarch64Ops()
        elif pwndbg.gdblib.arch.name == "x86-64":
            _arch_ops = x86_64Ops()

    return _arch_ops


@requires_debug_syms()
def page_size() -> int:
    ops = arch_ops()
    if ops:
        return ops.page_size()
    else:
        raise NotImplementedError()


@requires_debug_syms()
def per_cpu(addr: gdb.Value, cpu: Optional[int] = None):
    ops = arch_ops()
    if ops:
        return ops.per_cpu(addr, cpu)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def virt_to_phys(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_phys(virt)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def phys_to_virt(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_virt(phys)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def phys_to_pfn(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_pfn(phys)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def pfn_to_phys(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_phys(pfn)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def pfn_to_page(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_page(pfn)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def page_to_pfn(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_pfn(page)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def phys_to_page(phys: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.phys_to_page(phys)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def page_to_phys(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_phys(page)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def virt_to_page(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_page(virt)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def page_to_virt(page: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.page_to_virt(page)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def pfn_to_virt(pfn: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.pfn_to_virt(pfn)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def virt_to_pfn(virt: int) -> int:
    ops = arch_ops()
    if ops:
        return ops.virt_to_pfn(virt)
    else:
        raise NotImplementedError()


@requires_debug_syms()
def paging_enabled() -> bool:
    arch_name = pwndbg.gdblib.arch.name
    if arch_name == "x86-64":
        return x86_64Ops.paging_enabled()
    elif arch_name == "aarch64":
        return Aarch64Ops.paging_enabled()
    else:
        raise NotImplementedError()


@requires_debug_syms()
def num_numa_nodes() -> int:
    """Returns the number of NUMA nodes that are online on the system"""
    kc = kconfig()
    if "CONFIG_NUMA" not in kc:
        return 1

    max_nodes = 1 << int(kc["CONFIG_NODES_SHIFT"])
    if max_nodes == 1:
        return 1

    return int(gdb.lookup_global_symbol("nr_online_nodes").value())
