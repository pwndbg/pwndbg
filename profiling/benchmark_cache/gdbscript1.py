import pwndbg

if hasattr(pwndbg.lib, 'memoize'):
    # In old versions of Pwndbg, before https://github.com/pwndbg/pwndbg/pull/1678
    clear_caches = pwndbg.lib.memoize.reset
    print("Using old version of Pwndbg with lib.memoize")
else:
    clear_caches = pwndbg.lib.cache.clear_caches
    print("Using new version of Pwndbg with lib.cache")


pwndbg.profiling.profiler.start()
for i in range(500):
    gdb.execute("pi pwndbg.commands.context.context()", to_string=True)
    clear_caches()
pwndbg.profiling.profiler.stop('profile.prof')
