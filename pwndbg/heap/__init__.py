import pwndbg.color.message as message
import pwndbg.gdblib.config
import pwndbg.gdblib.symbol
import pwndbg.heap.heap

current = None


def add_heap_param(
    name, default, set_show_doc, *, help_docstring=None, param_class=None, enum_sequence=None
):
    return pwndbg.gdblib.config.add_param(
        name,
        default,
        set_show_doc,
        help_docstring=help_docstring,
        param_class=param_class,
        enum_sequence=enum_sequence,
        scope="heap",
    )


main_arena = add_heap_param("main-arena", "0", "&main_arena for heuristics")

thread_arena = add_heap_param("thread-arena", "0", "*thread_arena for heuristics")

mp_ = add_heap_param("mp", "0", "&mp_ for heuristics")

tcache = add_heap_param("tcache", "0", "*tcache for heuristics")

global_max_fast = add_heap_param("global-max-fast", "0", "&global_max_fast for heuristics")

symbol_list = [main_arena, thread_arena, mp_, tcache, global_max_fast]

heap_chain_limit = add_heap_param("heap-dereference-limit", 8, "number of bins to dereference")

resolve_heap_via_heuristic = add_heap_param(
    "resolve-heap-via-heuristic", False, "Resolve missing heap related symbols via heuristics"
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
