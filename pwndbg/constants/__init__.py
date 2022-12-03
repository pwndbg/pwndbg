import pwndbg.gdblib.arch

from . import aarch64
from . import amd64
from . import arm
from . import i386
from . import mips
from . import thumb

arches = {"arm": arm, "armcm": arm, "i386": i386, "mips": mips, "x86-64": amd64, "aarch64": aarch64}


def syscall(number, arch):
    """
    Given a syscall number and architecture, returns the name of the syscall.
    E.g. execve == 59 on x86-64
    """
    arch = arches.get(arch, None)

    if arch is None:
        return None

    prefix = "__NR_"

    for k, v in arch.__dict__.items():
        if v != number:
            continue

        if not k.startswith(prefix):
            continue

        return k[len(prefix) :].lower()

    return None
