import gdb
import pwndbg.memoize
import pwndbg.memory
import pwndbg.ida

@pwndbg.memoize.reset_on_objfile
def get(address):
    """
    Retrieve the textual name for a symbol
    """
    # Fast path
    if address < pwndbg.memory.MMAP_MIN_ADDR:
        return ''

    # This sucks, but there's not a GDB API for this.
    result = gdb.execute('info symbol %#x' % int(address), to_string=True, from_tty=False)

    if result.startswith('No symbol'):
        res =  pwndbg.ida.Name(address) or pwndbg.ida.GetFuncOffset(address)
        return res or ''

    # Expected format looks like this:
    # main in section .text of /bin/bash
    # main + 3 in section .text of /bin/bash
    # system + 1 in section .text of /lib/x86_64-linux-gnu/libc.so.6
    # No symbol matches system-1.
    a, b, c, _ = result.split(None, 3)


    if b == '+':
        return "%s+%s" % (a, c)
    if b == 'in':
        return a

    return ''

# last = None
# count = 0

# @pwndbg.events.stop
# def on_stop():
#     global last
#     if last is not get.cache:
#         print("DIFFERENT!",last,get.cache)
#         last = get.cache
#     print(get.cache)

# def trace(*a,**kw):
#     with open('log.txt','a+') as f:
#         import traceback
#         f.write('\n'.join(traceback.format_stack()))
#     global count
#     count += 1

# get.clear = trace
# get.cache.clear = trace