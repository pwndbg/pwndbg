from __future__ import annotations

from typing import Any
from typing import Sequence

import pwndbg
import pwndbg.aglib.heap.heap
import pwndbg.aglib.proc
import pwndbg.lib.config
from pwndbg.color import message
from pwndbg.dbg import EventType
from pwndbg.lib.config import Scope

current: pwndbg.aglib.heap.heap.MemoryAllocator | None = None


def add_heap_param(
    name: str,
    default: Any,
    set_show_doc: str,
    *,
    help_docstring: str = "",
    param_class: int | None = None,
    enum_sequence: Sequence[str] | None = None,
):
    return pwndbg.config.add_param(
        name,
        default,
        set_show_doc,
        help_docstring=help_docstring,
        param_class=param_class,
        enum_sequence=enum_sequence,
        scope=Scope.heap,
    )


main_arena = add_heap_param("main-arena", "0", "the address of main_arena")

thread_arena = add_heap_param("thread-arena", "0", "the address pointed by thread_arena")

mp_ = add_heap_param("mp", "0", "the address of mp_")

tcache = add_heap_param("tcache", "0", "the address pointed by tcache")

global_max_fast = add_heap_param("global-max-fast", "0", "the address of global_max_fast")

symbol_list = [main_arena, thread_arena, mp_, tcache, global_max_fast]

heap_chain_limit = add_heap_param(
    "heap-dereference-limit",
    8,
    "number of chunks to dereference in each bin",
    param_class=pwndbg.lib.config.PARAM_UINTEGER,
)

heap_corruption_check_limit = add_heap_param(
    "heap-corruption-check-limit",
    64,
    "amount of chunks to traverse for the bin corruption check",
    param_class=pwndbg.lib.config.PARAM_UINTEGER,
    help_docstring="""
The bins are traversed both forwards and backwards.
""",
)

if pwndbg.dbg.name() == pwndbg.dbg_mod.DebuggerType.GDB:
    extra_hint_for_gdb = """
In addition, even you have the debug symbols of libc, you might still see the
following warning when debugging a multi-threaded program:
```
warning: Unable to find libthread_db matching inferior's thread library, thread
debugging will not be available.
```

You'll need to ensure that the correct `libthread_db.so` is loaded. To do this,
set the search path using:
```
set libthread-db-search-path <path having correct libthread_db.so>
```
Then, restart your program to enable proper thread debugging.
"""
else:
    extra_hint_for_gdb = ""

resolve_heap_via_heuristic = add_heap_param(
    "resolve-heap-via-heuristic",
    "auto",
    "the strategy to resolve heap via heuristic",
    help_docstring="""\
Values explained:

+ `auto` - pwndbg will try to use heuristics if debug symbols are missing
+ `force` - pwndbg will always try to use heuristics, even if debug symbols are available
+ `never` - pwndbg will never use heuristics to resolve the heap

If the output of the heap related command produces errors with heuristics, you
can try manually setting the libc symbol addresses.
For this, see the `heap_config` command output and set the `main_arena`, `mp_`,
`global_max_fast`, `tcache` and `thread_arena` addresses.

Note: pwndbg will generate more reliable results with proper debug symbols.
Therefore, when debug symbols are missing, you should try to install them first
if you haven't already.

They can probably be installed via the package manager of your choice.
See also: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html .

E.g. on Ubuntu/Debian you might need to do the following steps (for 64-bit and
32-bit binaries):
```bash
sudo apt-get install libc6-dbg
sudo dpkg --add-architecture i386
sudo apt-get install libc-dbg:i386
```
If you used setup.sh on Arch based distro you'll need to do a power cycle or set
environment variable manually like this:
```bash
export DEBUGINFOD_URLS=https://debuginfod.archlinux.org
```
"""
    + extra_hint_for_gdb,
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["auto", "force", "never"],
)
del extra_hint_for_gdb


@pwndbg.dbg.event_handler(EventType.START)
def update() -> None:
    resolve_heap(is_first_run=True)


@pwndbg.dbg.event_handler(EventType.EXIT)
def reset() -> None:
    global current
    # Re-initialize the heap
    if current:
        current = type(current)()
    for symbol in symbol_list:
        symbol.value = "0"


@pwndbg.config.trigger(resolve_heap_via_heuristic)
def resolve_heap(is_first_run: bool = False) -> None:
    import pwndbg.aglib.heap.ptmalloc

    global current
    if resolve_heap_via_heuristic == "force":
        current = pwndbg.aglib.heap.ptmalloc.HeuristicHeap()
        if not is_first_run and pwndbg.aglib.proc.alive and current.libc_has_debug_syms():
            print(
                message.warn(
                    "You are going to resolve the heap via heuristic even though you have libc debug symbols."
                    " This is not recommended!"
                )
            )
    else:
        current = pwndbg.aglib.heap.ptmalloc.DebugSymsHeap()
