import pwndbg.config
import pwndbg.color.message as message
import pwndbg.heap.heap
import pwndbg.symbol

current = None

heap_chain_limit = pwndbg.config.Parameter('heap-dereference-limit', 8, 'number of bins to dereference')

resolve_via_heuristic = pwndbg.config.Parameter('resolve-via-heuristic', False, 'Resolve some missing symbols via heuristics')

@pwndbg.events.start
def update():
    resolve_heap(is_first_run=True)

@pwndbg.events.stop
@pwndbg.events.new_objfile
def clear():
    global current
    # Re-initialize the heap
    if current:
        current = type(current)()

@pwndbg.config.Trigger([resolve_via_heuristic])
def resolve_heap(is_first_run=False):
    import pwndbg.heap.ptmalloc
    global current
    if resolve_via_heuristic:
        current = pwndbg.heap.ptmalloc.HeuristicHeap()
        if not is_first_run and pwndbg.proc.alive and current.libc_has_debug_syms():
            print(message.warn("You are going to resolve the heap via heuristic even though you have libc debug symbols. This is not recommended!"))
        else:
            print(message.warn("You are going to resolve the heap via heuristic. This might not work in all cases."))
    else:
        current = pwndbg.heap.ptmalloc.DebugSymsHeap()
