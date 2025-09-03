from __future__ import annotations

import zlib
from collections import UserDict
from typing import Any
from typing import Dict

import pwndbg.aglib
import pwndbg.aglib.kernel
import pwndbg.aglib.symbol


def parse_config(config_text: bytes) -> Dict[str, str]:
    res: Dict[str, str] = {}

    for line in config_text.split(b"\n"):
        if b"=" in line:
            config_name, config_val = line.split(b"=", 1)
            res[config_name.decode("ascii")] = config_val.decode("ascii")

    return res


def parse_compresed_config(compressed_config: bytes) -> Dict[str, str]:
    config_text = zlib.decompress(compressed_config, 16)
    return parse_config(config_text)


def config_to_key(name: str) -> str:
    return "CONFIG_" + name.upper()


class Kconfig(UserDict):  # type: ignore[type-arg]
    def __init__(self, compressed_config: bytes | None, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if compressed_config is not None:
            self.data = parse_compresed_config(compressed_config)
            return
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

    def get_key(self, name: str) -> str | None:
        # First attempt to lookup the value assuming the user passed in a name
        # like 'debug_info', then attempt to lookup the value assuming the user
        # passed in a value like `config_debug_info` or `CONFIG_DEBUG_INFO`
        key = config_to_key(name)
        if key in self.data:
            return key
        elif name.upper() in self.data:
            return name.upper()
        elif name in self.data:
            return name

        return None

    def __getitem__(self, name: str):
        key = self.get_key(name)
        if key:
            return self.data[key]

        raise KeyError(f"Key {name} not found")

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        return self.get_key(name) is not None

    def __getattr__(self, name: str):
        return self.get(name)

    @property
    def CONFIG_SLUB_TINY(self) -> bool:
        krelease = pwndbg.aglib.kernel.krelease()
        if krelease is not None and krelease < (6, 2): # config added after v6.2
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
        def __helper(name):
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

    def update_with_file(self, file_path):
        for line in open(file_path, "r").read().splitlines():
            split = line.split("=")
            if len(line) == 0 or line[0] == "#" or len(split) != 2:
                continue
            self.data[split[0]] = split[1]
