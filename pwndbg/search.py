import gdb
import struct
import pwndbg.memory
import pwndbg.vmmap
import pwndbg.typeinfo

def search(searchfor):
    value = searchfor
    size  = None

    if searchfor.isdigit():
        searchfor = int(searchfor)
    elif all(c in 'xABCDEFabcdef0123456789' for c in searchfor):
        searchfor = int(searchfor, 16)

    if isinstance(searchfor, int):
        if searchfor <= 0xffffffff:
            searchfor = struct.pack('I', searchfor)
        elif searchfor <= 0xffffffffffffffff:
            searchfor = struct.pack('L', searchfor)

    i = gdb.selected_inferior()

    maps = pwndbg.vmmap.get()
    hits = []
    for vmmap in maps:
        start = vmmap.vaddr
        end   = start + vmmap.memsz
        while True:
            if not pwndbg.memory.peek(start):
                break
            start = i.search_memory(start, end - start, searchfor)
            if start is None:
                break
            hits.append(start)
            start += len(searchfor)
    return hits