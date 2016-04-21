import gdb
import pwndbg.events
import pwndbg.file
import pwndbg.remote

def is_android():
    if pwndbg.file.get('/system/etc/hosts'):
        return True

    return False

@pwndbg.events.start
def sysroot():
    if is_android():
        gdb.execute('set sysroot remote:/')
