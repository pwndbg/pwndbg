from __future__ import annotations

import functools
import re
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
import pwndbg.aglib.qemu
import pwndbg.aglib.search
import pwndbg.aglib.symbol
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.kernel.structs

if TYPE_CHECKING:
    import pwndbg.aglib.kernel.arch
    import pwndbg.aglib.kernel.kconfig_mod
    import pwndbg.aglib.kernel.vmmap

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


@pwndbg.lib.cache.cache_until("start")
def nproc() -> int:
    """Returns the number of processing units available, similar to nproc(1)"""
    return len(pwndbg.dbg.selected_inferior().send_monitor("info cpus").splitlines())


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
            assert version_addr
            result = pwndbg.aglib.memory.string(version_addr).decode("ascii").strip()
            assert len(result) > 0
            return result
    except Exception:
        pass
    mapping = pwndbg.aglib.kernel.vmmap.first_kernel_ro_page()
    if mapping is None:
        return None
    version_addr = next(pwndbg.aglib.search.search(b"Linux version", mappings=[mapping]), None)
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

    if base is None or limit is None:
        return

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


@requires_debug_symbols("__per_cpu_offset", "nr_iowait_cpu", checkall=False)
def per_cpu(addr: int | pwndbg.dbg_mod.Value, cpu: int | None = None) -> pwndbg.dbg_mod.Value:
    if cpu is None:
        cpu = current_cpu()

    per_cpu_offset = symbol.per_cpu_offset
    offset = pwndbg.aglib.memory.u(per_cpu_offset + (cpu * 8))
    per_cpu_addr = pwndbg.aglib.arch.unsigned(int(addr) + offset)
    if isinstance(addr, pwndbg.dbg_mod.Value):
        return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr, addr.type)
    return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr)


def num_numa_nodes() -> int:
    """Returns the number of NUMA nodes that are online on the system"""
    kc = pwndbg.aglib.kernel.kconfig_mod.kconfig()

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

    val = pwndbg.aglib.kernel.try_usymbol("nr_online_nodes", 32)
    if val is None:
        return 1

    return val


paging: pwndbg.aglib.kernel.arch.Paging
symbol: pwndbg.aglib.kernel.arch.ArchSymbols


@pwndbg.dbg.event_handler(pwndbg.dbg_mod.EventType.START)
def set_paging_and_symbol_on_start():
    if not pwndbg.aglib.qemu.is_qemu_kernel():
        return
    global paging, symbol
    paging = pwndbg.aglib.kernel.arch.select_paging()
    symbol = pwndbg.aglib.kernel.arch.select_symbol()


@pwndbg.lib.cache.cache_until("stop")
def current_task(cpu: int | None = None) -> int | None:
    result = symbol.current_task
    if result is None:
        return None
    if pwndbg.aglib.arch.name == "aarch64":
        # TODO: how to get the kcurrent for different cpus
        return result
    ptr = int(per_cpu(result, cpu=cpu))
    return pwndbg.aglib.memory.read_pointer_width(ptr)


POSSIBLE_ZONE_NAMES = (
    "DMA",
    "DMA32",
    "Normal",
    "HighMem",
    "Movable",
    "Device",
)


@pwndbg.lib.cache.cache_until("objfile")
def migratetype_names() -> tuple[str, ...]:
    names = [
        "Unmovable",
        "Movable",
        "Reclaimable",
        "HighAtomic",
    ]
    kconfig = pwndbg.aglib.kernel.kconfig_mod.kconfig()
    if "CONFIG_CMA" in kconfig:
        names.append("CMA")
    if "CONFIG_MEMORY_ISOLATION" in kconfig:
        names.append("Isolate")
    return tuple(names)


# try getting value of a symbol as an unsigned integer
def try_usymbol(name: str, size: int | None = None) -> int | None:
    if not pwndbg.aglib.kernel.has_debug_symbols():
        return None
    try:
        if pwndbg.aglib.kernel.has_debug_info():
            return pwndbg.aglib.symbol.lookup_symbol_value(name)

        symbol = pwndbg.aglib.symbol.lookup_symbol_addr(name)
        if symbol is None:
            return None

        if size is None:
            size = pwndbg.aglib.arch.ptrbits

        if size == 8:
            return pwndbg.aglib.memory.u(symbol)
        if size == 16:
            return pwndbg.aglib.memory.u16(symbol)
        if size == 32:
            return pwndbg.aglib.memory.u32(symbol)

        return pwndbg.aglib.memory.u64(symbol)
    except Exception:
        # for kpti
        return None


@requires_debug_symbols("zone_names", default=4)
def nzones() -> int:
    _zone_names = pwndbg.aglib.symbol.lookup_symbol_addr("zone_names")
    for i in range(len(POSSIBLE_ZONE_NAMES) + 1):
        char_ptr = pwndbg.aglib.memory.u64(_zone_names + i * 8)
        if pwndbg.aglib.memory.string(char_ptr).decode() not in POSSIBLE_ZONE_NAMES:
            return i
    assert False, "cannot determine the number of zones"


def nmtypes() -> int:
    return len(migratetype_names())


def node_data_pointer() -> pwndbg.dbg_mod.Value | None:
    addr = symbol.node_data
    if addr is None:
        return None
    node_data = pwndbg.aglib.memory.get_typed_pointer("struct pglist_data", addr)
    if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig_mod.kconfig():
        return node_data.cast(node_data.type.pointer())
    return node_data


def npcplist() -> int:
    """returns NR_PCP_LISTS (https://elixir.bootlin.com/linux/v6.13/source/include/linux/mmzone.h#L671)"""
    if not pwndbg.aglib.kernel.has_debug_info():
        if (kversion := krelease()) and kversion >= (5, 14):
            return 12
        return 3
    node_data = node_data_pointer()
    if not node_data or "CONFIG_NUMA" not in pwndbg.aglib.kernel.kconfig_mod.kconfig():
        node_data0 = node_data
    else:
        node_data0 = node_data.dereference()
    zone = node_data0[0]["node_zones"][0]
    # index 0 should always exist
    if zone.type.has_field("per_cpu_pageset"):
        lists = zone["per_cpu_pageset"]["lists"]
        return lists.type.array_len
    if zone.type.has_field("pageset"):
        lists = zone["pageset"]["pcp"]["lists"]
        return lists.type.array_len
    return 0


def kversion_cint(kversion: tuple[int, ...] | None = None) -> int | None:
    if kversion is None:
        kversion = pwndbg.aglib.kernel.krelease()
    if kversion is None or len(kversion) != 3:
        return None
    x, y, z = kversion
    return ((x) * 65536) + ((y) * 256) + (z)
