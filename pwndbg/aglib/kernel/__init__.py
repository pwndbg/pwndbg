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
import pwndbg.aglib.kernel.arch.paging as _paging
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.search
import pwndbg.aglib.structures
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.kernel.structs
import pwndbg.lib.memory
from pwndbg.lib import Status
from pwndbg.lib import TypeNotFoundError
from pwndbg.lib import TypeNotRecoveredError

if TYPE_CHECKING:
    import pwndbg.aglib.kernel.kconfig_mod
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
            if requires_kbase and paging.kbase is None:
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
    base = paging.kbase
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

        result = next(pwndbg.aglib.search.search(b"Linux version", mappings=[mapping]), None)

        if result:
            return mapping
    # optimization: observe that the first Linux kernel region is the kernel text so search it last
    # it now finds the first ro page almost instantly even for kernels that are partially initialized
    # should find it within the first few page chunks if debugging linux kernel (reason for [:10])
    for mapping in fallback_mappings[1:10] + [fallback_mappings[0]]:
        # this loop handles when the kernel has not finished initialization
        # and the permission of the first ro page has not been properly set
        result = next(pwndbg.aglib.search.search(b"Linux version", mappings=[mapping]), None)

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
            result = next(pwndbg.aglib.search.search(b"IKCFG_ST", mappings=[mapping]), None)

        if result is not None:
            config_start = result + len("IKCFG_ST")
            config_end = next(pwndbg.aglib.search.search(b"IKCFG_ED", start=config_start), None)
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
            assert version_addr
            result = pwndbg.aglib.memory.string(version_addr).decode("ascii").strip()
            assert len(result) > 0
            return result
    except Exception:
        pass
    mapping = first_kernel_ro_page()
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


@requires_debug_symbols("__per_cpu_offset", "nr_iowait_cpu", checkall=False)
def per_cpu(
    addr: int | pwndbg.dbg_mod.Value, cpu: int | None = None
) -> pwndbg.dbg_mod.Value | None:
    if cpu is None:
        cpu = current_cpu()

    per_cpu_offset = pwndbg.aglib.kernel.per_cpu_offset()
    if per_cpu_offset is None:
        return None

    offset = pwndbg.aglib.memory.u(per_cpu_offset + (cpu * 8))
    per_cpu_addr = pwndbg.aglib.arch.unsigned(int(addr) + offset)
    if isinstance(addr, pwndbg.dbg_mod.Value):
        return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr, addr.type)
    return pwndbg.dbg.selected_inferior().create_value(per_cpu_addr)


# TODO: on start: refresh
paging: _paging.Paging = _paging.select()


@pwndbg.lib.cache.cache_until("start")
def arch_symbols() -> pwndbg.aglib.kernel.symbol.ArchSymbols | None:
    if pwndbg.aglib.arch.name == "aarch64":
        return pwndbg.aglib.kernel.symbol.Aarch64Symbols()
    if pwndbg.aglib.arch.name == "x86-64":
        return pwndbg.aglib.kernel.symbol.x86_64Symbols()
    return None


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
