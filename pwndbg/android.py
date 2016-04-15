import pwndbg.file
import pwndbg.remote

def is_android():
    if pwndbg.file.get('/system/etc/hosts'):
        return True

    return False