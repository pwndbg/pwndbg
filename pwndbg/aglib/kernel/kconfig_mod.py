from __future__ import annotations

import zlib
from collections import UserDict
from typing import Any

import pwndbg.aglib
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.vmmap
import pwndbg.aglib.memory
import pwndbg.aglib.nearpc
import pwndbg.aglib.search
import pwndbg.aglib.symbol
import pwndbg.lib.cache
from pwndbg.color import message
from pwndbg.dbg_mod import EventType


def parse_config(config_text: bytes) -> dict[str, str]:
    res: dict[str, str] = {}

    for line in config_text.split(b"\n"):
        if b"=" in line:
            config_name, config_val = line.split(b"=", 1)
            res[config_name.decode("ascii")] = config_val.decode("ascii")

    return res


def parse_compresed_config(compressed_config: bytes | bytearray) -> dict[str, str]:
    config_text = zlib.decompress(compressed_config, 16)
    return parse_config(config_text)


def config_to_key(name: str) -> str:
    return "CONFIG_" + name.upper()


class Kconfig(UserDict):  # type: ignore[type-arg]
    def __init__(
        self, compressed_config: bytes | bytearray | None, *args: Any, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        if compressed_config is not None:
            try:
                self.data = parse_compresed_config(compressed_config)
                return
            except Exception as e:
                print(
                    message.error(
                        f"decompression of kconfig failed with error {str(e)}, please report."
                    )
                )
        if self.CONFIG_SLUB_TINY:
            self.data["CONFIG_SLUB_TINY"] = "y"
        if self.CONFIG_SLUB_CPU_PARTIAL:
            self.data["CONFIG_SLUB_CPU_PARTIAL"] = "y"
        if self.CONFIG_MEMCG:
            self.data["CONFIG_MEMCG"] = "y"
        if self.CONFIG_SLAB_FREELIST_RANDOM:
            self.data["CONFIG_SLAB_FREELIST_RANDOM"] = "y"
        if self.CONFIG_HARDENED_USERCOPY:
            self.data["CONFIG_HARDENED_USERCOPY"] = "y"
        if self.CONFIG_SLAB_FREELIST_HARDENED:
            self.data["CONFIG_SLAB_FREELIST_HARDENED"] = "y"
        if self.CONFIG_NUMA:
            self.data["CONFIG_NUMA"] = "y"
        if self.CONFIG_KASAN_GENERIC:
            self.data["CONFIG_KASAN_GENERIC"] = "y"
        if self.CONFIG_SMP:
            self.data["CONFIG_SMP"] = "y"
        if self.CONFIG_CMA:
            self.data["CONFIG_CMA"] = "y"
        if self.CONFIG_MEMORY_ISOLATION:
            self.data["CONFIG_MEMORY_ISOLATION"] = "y"
        if self.CONFIG_KASAN:
            self.data["CONFIG_KASAN"] = "y"
        if self.CONFIG_SYSFS:
            self.data["CONFIG_SYSFS"] = "y"
        if self.CONFIG_DEBUG_FS:
            self.data["CONFIG_DEBUG_FS"] = "y"
        if self.CONFIG_SECURITY:
            self.data["CONFIG_SECURITY"] = "y"
        if self.CONFIG_STACKPROTECTOR:
            self.data["CONFIG_STACKPROTECTOR"] = "y"
        if self.CONFIG_RANDSTRUCT:
            self.data["CONFIG_RANDSTRUCT"] = "y"
        if self.CONFIG_SLAB_VIRTUAL:
            self.data["CONFIG_SLAB_VIRTUAL"] = "y"

    def get_key(self, name: str) -> str | None:
        # First attempt to lookup the value assuming the user passed in a name
        # like 'debug_info', then attempt to lookup the value assuming the user
        # passed in a value like `config_debug_info` or `CONFIG_DEBUG_INFO`
        key = config_to_key(name)
        if key in self.data:
            return key
        if name.upper() in self.data:
            return name.upper()
        if name in self.data:
            return name

        return None

    def __getitem__(self, name: str) -> str:
        key = self.get_key(name)
        if key:
            return self.data[key]

        raise KeyError(f"Key {name} not found")

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        return self.get_key(name) is not None

    def __getattr__(self, name: str) -> object:
        return self.get(name)

    @property
    def CONFIG_SLUB_TINY(self) -> bool:
        krelease = pwndbg.aglib.kernel.krelease()
        if krelease is not None and krelease < (6, 2):  # config added after v6.2
            return False
        return pwndbg.aglib.symbol.lookup_symbol("deactivate_slab") is None

    @property
    def CONFIG_SLUB_CPU_PARTIAL(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("put_cpu_partial") is not None

    @property
    def CONFIG_MEMCG(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("kpagecgroup_proc_ops") is not None

    @property
    def CONFIG_SLAB_FREELIST_RANDOM(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("init_cache_random_seq") is not None

    @property
    def CONFIG_HARDENED_USERCOPY(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("__check_heap_object") is not None

    @property
    def CONFIG_SLAB_FREELIST_HARDENED(self) -> bool:
        def __helper(name) -> bool:
            addr = pwndbg.aglib.symbol.lookup_symbol_addr(name)
            if addr is not None:
                for instr in pwndbg.aglib.nearpc.nearpc(addr, 40):
                    if "get_random" in instr:
                        return True
            return False

        return any(
            __helper(name)
            for name in (
                "kmem_cache_open",
                "do_kmem_cache_create",
                "__kmem_cache_create",
            )
        )

    @property
    def CONFIG_NUMA(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("node_reclaim") is not None

    @property
    def CONFIG_KASAN_GENERIC(self) -> bool:
        # TODO: have a kernel build that tests this
        krelease = pwndbg.aglib.kernel.krelease()
        if krelease is None:
            return False
        if krelease > (6, 1) or krelease < (5, 11):
            return pwndbg.aglib.symbol.lookup_symbol("kasan_cache_create") is not None
        return pwndbg.aglib.symbol.lookup_symbol("__kasan_cache_create") is not None

    @property
    def CONFIG_KASAN(self) -> bool:
        # TODO: have a kernel build that tests this
        if self.CONFIG_KASAN_GENERIC:
            return True
        return pwndbg.aglib.symbol.lookup_symbol("__kasan_krealloc") is not None

    @property
    def CONFIG_SMP(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("pcpu_get_vm_areas") is not None

    @property
    def CONFIG_CMA(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("init_cma_reserved_pageblock") is not None

    @property
    def CONFIG_MEMORY_ISOLATION(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("start_isolate_page_range") is not None

    @property
    def CONFIG_SYSFS(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("sysfs_kf_seq_show") is not None

    @property
    def CONFIG_DEBUG_FS(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("debugfs_attr_read") is not None

    @property
    def CONFIG_SECURITY(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("security_inode_init_security") is not None

    @property
    def CONFIG_STACKPROTECTOR(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("put_task_stack") is not None

    @property
    def CONFIG_RANDSTRUCT(self) -> bool:
        krelease = pwndbg.aglib.kernel.krelease()
        if krelease is None or krelease < (5, 19):
            return False
        val = pwndbg.aglib.kernel.try_usymbol("tainted_mask")
        return val is not None and val != 0

    @property
    def CONFIG_SLAB_VIRTUAL(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("slub_addr_base") is not None

    @property
    def CONFIG_LOCKDEP(self) -> bool:
        return pwndbg.aglib.symbol.lookup_symbol("fs_reclaim_acquire") is not None

    def update_with_file(self, file_path) -> None:
        for line in open(file_path).read().splitlines():
            split = line.split("=")
            if len(line) == 0 or line[0] == "#" or len(split) != 2:
                continue
            self.data[split[0]] = split[1]


_kconfig: Kconfig | None = None


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def reset_config() -> None:
    global _kconfig
    _kconfig = None


@pwndbg.lib.cache.cache_until("objfile")
def kconfig() -> Kconfig:
    global _kconfig
    config_start, config_end = None, None
    if pwndbg.aglib.kernel.has_debug_symbols():
        config_start = pwndbg.aglib.symbol.lookup_symbol_addr("kernel_config_data")
        config_end = pwndbg.aglib.symbol.lookup_symbol_addr("kernel_config_data_end")
    else:
        mapping = pwndbg.aglib.kernel.vmmap.first_kernel_ro_page()
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
        _kconfig = Kconfig(None)
        return _kconfig

    config_size = config_end - config_start

    compressed_config = pwndbg.aglib.memory.read(config_start, config_size)
    _kconfig = Kconfig(compressed_config)
    return _kconfig
