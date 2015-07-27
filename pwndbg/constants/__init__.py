import pwndbg.arch
from . import arm, aarch64, thumb, mips, amd64, i386

arches = {
    'arm': arm,
    'i386': i386,
    'mips': mips,
    'amd64': amd64,
    'aarch64': aarch64
}

def syscall(value):
    """
    Given a value for a syscall number (e.g. execve == 11), return
    the *name* of the syscall.
    """
    arch = arches.get(pwndbg.arch.current, None)

    if not arch:
        return None

    for k, v in arch.__dict__.items():
        if v == value and k.startswith('__NR_'):
            return k[len('__NR_'):].lower()

    return None
