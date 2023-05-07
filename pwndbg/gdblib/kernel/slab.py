import gdb

from pwndbg.gdblib.kernel.macros import for_each_entry


def caches():
    slab_caches = gdb.lookup_global_symbol("slab_caches").value()
    for slab_cache in for_each_entry(slab_caches, "struct kmem_cache", "list"):
        yield slab_cache


def get_cache(target_name: str):
    slab_caches = gdb.lookup_global_symbol("slab_caches").value()
    for slab_cache in for_each_entry(slab_caches, "struct kmem_cache", "list"):
        if target_name == slab_cache["name"].string():
            return slab_cache


def get_slab_key() -> str:
    # In Linux kernel version 5.17 a slab struct was introduced instead of the previous page struct
    try:
        gdb.lookup_type("struct slab")
        return "slab"
    except gdb.error:
        return "page"


OO_SHIFT = 16
OO_MASK = (1 << OO_SHIFT) - 1


def oo_order(x: int) -> int:
    return int(x) >> OO_SHIFT


def oo_objects(x: int) -> int:
    return int(x) & OO_MASK
