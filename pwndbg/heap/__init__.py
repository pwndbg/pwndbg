import pwndbg.color.message as message
import pwndbg.config
import pwndbg.heap.heap
import pwndbg.symbol

current = None

heap_chain_limit = pwndbg.config.Parameter('heap-dereference-limit', 8, 'number of bins to dereference')

resolve_via_heuristic = pwndbg.config.Parameter('resolve-via-heuristic', False,
                                                'Resolve some missing symbols via heuristics')

main_arena = pwndbg.config.Parameter('main_arena', "0", 'main_arena address for heuristics')

thread_arena = pwndbg.config.Parameter('thread_arena', "0", 'thread_arena value for heuristics')

mp_ = pwndbg.config.Parameter('mp_', "0", 'mp_ address for heuristics')

tcache = pwndbg.config.Parameter('tcache', "0", 'tcache value for heuristics')

global_max_fast = pwndbg.config.Parameter('global_max_fast', "0", 'global_max_fast address for heuristics')

symbol_list = [main_arena, thread_arena, mp_, tcache, global_max_fast]


@pwndbg.config.Trigger(symbol_list)
def parse_config2address():
    # Somehow, we can't use integer config because the integer is too big and will cause out of range error for GDB API
    # So we convert the string to a int manually
    for symbol in symbol_list:
        if not isinstance(symbol.value, str):
            continue
        address_str = symbol.value.strip()
        if address_str == "0":
            continue
        try:
            if address_str.startswith("0b"):
                address = int(address_str, 2)
            elif address_str.startswith("0o"):
                address = int(address_str, 8)
            elif address_str.startswith("0x"):
                address = int(address_str, 16)
            else:
                address = int(address_str)
        except ValueError:
            symbol.value = "0"
            raise ValueError("Please input a valid integer literal string")
        symbol.value = address


@pwndbg.events.start
def update():
    resolve_heap(is_first_run=True)


@pwndbg.events.stop
@pwndbg.events.new_objfile
def reset():
    global current
    # Re-initialize the heap
    if current:
        current = type(current)()
    for symbol in symbol_list:
        symbol.value = "0"


@pwndbg.config.Trigger([resolve_via_heuristic])
def resolve_heap(is_first_run=False):
    import pwndbg.heap.ptmalloc
    global current
    if resolve_via_heuristic:
        current = pwndbg.heap.ptmalloc.HeuristicHeap()
        if not is_first_run and pwndbg.proc.alive and current.libc_has_debug_syms():
            print(message.warn(
                "You are going to resolve the heap via heuristic even though you have libc debug symbols."
                " This is not recommended!")
            )
        else:
            print(message.warn("You are going to resolve the heap via heuristic. This might not work in all cases."))
    else:
        current = pwndbg.heap.ptmalloc.DebugSymsHeap()
