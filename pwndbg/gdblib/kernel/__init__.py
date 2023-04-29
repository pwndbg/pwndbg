import functools
import math
import re
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

    def phys_to_page(self, phys: int) -> int:
        raise NotImplementedError()

    def page_to_phys(self, page: int) -> int:
        raise NotImplementedError()

    def virt_to_page(self, virt: int) -> int:
        return phys_to_page(virt_to_phys(virt))

    def page_to_virt(self, page: int) -> int:
        return phys_to_virt(page_to_phys(page))


class x86_64Ops(ArchOps):
    def __init__(self) -> None:
        if "X86_5LEVEL" in kconfig() and "no5lvl" not in kcmdline():
            raise NotImplementedError("Level 5 page table support is not implemented")

        self.STRUCT_PAGE_SIZE = gdb.lookup_type("struct page").sizeof
        self.STRUCT_PAGE_SHIFT = int(math.log2(self.STRUCT_PAGE_SIZE))

        self.PAGE_OFFSET = 0xFFFF888000000000
        self.PHYSICAL_MASK_SHIFT = 52
        self.VIRTUAL_MASK_SHIFT = 47
        self.START_KERNEL_map = 0xFFFFFFFF80000000
        self.PAGE_SHIFT = 12
        self.phys_base = 0x1000000

    def per_cpu(self, addr: gdb.Value, cpu=None):
        if cpu is None:
            cpu = gdb.selected_thread().num - 1

        per_cpu_offset = pwndbg.gdblib.symbol.address("__per_cpu_offset")
        offset = pwndbg.gdblib.memory.u(per_cpu_offset + (cpu * 8))
        per_cpu_addr = (int(addr) + offset) % 2**64
        return gdb.Value(per_cpu_addr).cast(addr.type)

    def virt_to_phys(self, virt: int) -> int:
        if virt < self.__START_KERNEL_map:
            return virt - self.PAGE_OFFSET
        else:
            return (virt - self.__START_KERNEL_MAP) + self.phys_base

    def phys_to_virt(self, phys: int) -> int:
        return phys + self.PAGE_OFFSET

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.PAGE_SHIFT

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.PAGE_SHIFT

    def phys_to_page(self, phys: int) -> int:
        return (self.STRUCT_PAGE_SIZE * phys_to_pfn(phys)) + self.START_KERNEL_map

    def page_to_phys(self, page: int) -> int:
        return pfn_to_phys((page - self.START_KERNEL_map) >> self.STRUCT_PAGE_SHIFT)

    @staticmethod
    def paging_enabled() -> bool:
        return int(pwndbg.gdblib.regs.cr0) & BIT(31) != 0


class Aarch64Ops(ArchOps):
    def __init__(self) -> None:
        self.STRUCT_PAGE_SIZE = gdb.lookup_type("struct page").sizeof
        self.STRUCT_PAGE_SHIFT = int(math.log2(self.STRUCT_PAGE_SIZE))

        self.VA_BITS = int(kconfig()["ARM64_VA_BITS"])
        self.PAGE_SHIFT = int(kconfig()["CONFIG_ARM64_PAGE_SHIFT"])
        self.PAGE_SIZE = 1 << self.PAGE_SHIFT

        self.PHYS_OFFSET = pwndbg.gdblib.memory.u(pwndbg.gdblib.symbol.address("memstart_addr"))
        self.PAGE_OFFSET = (-1 << self.VA_BITS) + 2**64

        VA_BITS_MIN = 48 if self.VA_BITS > 48 else self.VA_BITS
        PAGE_END = (-1 << (VA_BITS_MIN - 1)) + 2**64
        VMEMMAP_SIZE = (PAGE_END - self.PAGE_OFFSET) >> (self.PAGE_SHIFT - self.STRUCT_PAGE_SHIFT)

        self.VMEMMAP_START = (-VMEMMAP_SIZE - 2 * 1024 * 1024) + 2**64

    def per_cpu(self, addr: gdb.Value, cpu=None):
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

    def phys_to_page(self, phys: int) -> int:
        return (self.STRUCT_PAGE_SIZE * phys_to_pfn(phys)) + self.VMEMMAP_START

    def page_to_phys(self, page: int) -> int:
        return pfn_to_phys((page - self.VMEMMAP_START) >> self.STRUCT_PAGE_SHIFT)

    @staticmethod
    def paging_enabled() -> bool:
        return int(pwndbg.gdblib.regs.SCTLR) & BIT(0) != 0


_arch_ops: ArchOps = None


@requires_debug_syms(default={})
@pwndbg.lib.cache.cache_until("start")
def arch_ops() -> ArchOps:
    global _arch_ops
    if _arch_ops is None:
        arch_name = pwndbg.gdblib.arch.name
        if pwndbg.gdblib.arch.name == "aarch64":
            _arch_ops = Aarch64Ops()
        elif pwndbg.gdblib.arch.name == "x86-64":
            _arch_ops = x86_64Ops()

    return _arch_ops


def per_cpu(addr: gdb.Value, cpu=None):
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.per_cpu(addr, cpu)
    else:
        raise NotImplementedError()


def virt_to_phys(virt: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.virt_to_phys(virt)
    else:
        raise NotImplementedError()


def phys_to_virt(phys: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.phys_to_virt(phys)
    else:
        raise NotImplementedError()


def phys_to_pfn(phys: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.phys_to_pfn(phys)
    else:
        raise NotImplementedError()


def pfn_to_phys(pfn: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.pfn_to_phys(pfn)
    else:
        raise NotImplementedError()


def phys_to_page(phys: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.phys_to_page(phys)
    else:
        raise NotImplementedError()


def page_to_phys(page: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.page_to_phys(page)
    else:
        raise NotImplementedError()


def virt_to_page(virt: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.virt_to_page(virt)
    else:
        raise NotImplementedError()


def page_to_virt(page: int) -> int:
    arch_name = pwndbg.gdblib.arch.name
    ops = arch_ops()
    if ops:
        return ops.page_to_virt(page)
    else:
        raise NotImplementedError()


def paging_enabled() -> bool:
    arch_name = pwndbg.gdblib.arch.name
    if arch_name == "x86-64":
        return x86_64Ops.paging_enabled()
    elif arch_name == "aarch64":
        return Aarch64Ops.paging_enabled()
    else:
        raise NotImplementedError()
