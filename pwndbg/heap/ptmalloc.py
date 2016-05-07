from __future__ import print_function
import gdb
import pwndbg.events
import pwndbg.typeinfo

malloc_chunk = None
malloc_state = None
mallinfo     = None

@pwndbg.events.new_objfile
def update():
  malloc_chunk = gdb.lookup_type('struct malloc_chunk')
  malloc_state = gdb.lookup_type('struct malloc_state')
  mallinfo = gdb.lookup_type('struct mallinfo')
