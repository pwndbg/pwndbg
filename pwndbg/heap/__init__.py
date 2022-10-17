import pwndbg.color.message as message
import pwndbg.gdblib.config
import pwndbg.gdblib.symbol
import pwndbg.heap.heap

current = None

main_arena = pwndbg.gdblib.config.add_param("main-arena", "0", "&main_arena for heuristics", "heap")

thread_arena = pwndbg.gdblib.config.add_param(
    "thread-arena", "0", "*thread_arena for heuristics", "heap"
)

mp_ = pwndbg.gdblib.config.add_param("mp", "0", "&mp_ for heuristics", "heap")

tcache = pwndbg.gdblib.config.add_param("tcache", "0", "*tcache for heuristics", "heap")

global_max_fast = pwndbg.gdblib.config.add_param(
    "global-max-fast", "0", "&global_max_fast for heuristics", "heap"
)

symbol_list = [main_arena, thread_arena, mp_, tcache, global_max_fast]

heap_chain_limit = pwndbg.gdblib.config.add_param(
    "heap-dereference-limit", 8, "number of bins to dereference", "heap"
)

resolve_heap_via_heuristic = pwndbg.gdblib.config.add_param(
    "resolve-heap-via-heuristic",
    False,
    "Resolve missing heap related symbols via heuristics",
    "heap",
)


@pwndbg.gdblib.events.start
def update():
    resolve_heap(is_first_run=True)


@pwndbg.gdblib.events.exit
def reset():
    global current
    # Re-initialize the heap
    if current:
        current = type(current)()
    for symbol in symbol_list:
        symbol.value = "0"


@pwndbg.gdblib.config.trigger(resolve_heap_via_heuristic)
def resolve_heap(is_first_run=False):
    import pwndbg.heap.ptmalloc

    global current
    if resolve_heap_via_heuristic:
        current = pwndbg.heap.ptmalloc.HeuristicHeap()
        if not is_first_run and pwndbg.gdblib.proc.alive and current.libc_has_debug_syms():
            print(
                message.warn(
                    "You are going to resolve the heap via heuristic even though you have libc debug symbols."
                    " This is not recommended!"
                )
            )
        else:
            print(
                message.warn(
                    "You are going to resolve the heap via heuristic. This might not work in all cases."
                )
            )
    else:
        current = pwndbg.heap.ptmalloc.DebugSymsHeap()
