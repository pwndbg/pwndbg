# kernel

WIP (more guidelines will be added)

## General guidelines

- When kernel version is checked to determine the code path to take, the latest version's path should be the default when kernel version is unavailable. e.g.
```py
# pwndbg/aglib/kernel/slab.py
    @property
    def node_caches(self) -> Generator[NodeCache, None, None]:
        """returns node caches for all NUMA nodes"""
        if (krelease := kernel.krelease()) and krelease < (7, 1):
            for node in range(kernel.num_numa_nodes()):
                yield NodeCache(self._slab_cache["node"][node], self, node)
        else:
            for node in range(kernel.num_numa_nodes()):
                yield NodeCache(self._slab_cache["per_node"][node]["node"], self, node)
```
- For experimental features, only the latest patch is supported, and is only supported when debuginfo is available. e.g. `CONFIG_SLAB_VIRTUAL` by google
- Architecture specific code should go into `pwndbg/aglib/kernel/arch`

