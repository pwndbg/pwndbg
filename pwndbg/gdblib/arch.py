import gdb

import pwndbg.proc
from pwndbg.gdblib import typeinfo
from pwndbg.lib.arch import Arch

# TODO: x86-64 needs to come before i386 in the current implementation, make
# this order-independent
ARCHS = ("x86-64", "i386", "aarch64", "mips", "powerpc", "sparc", "arm")

arch = Arch("i386", typeinfo.ptrsize, "little")


def _get_arch(ptrsize):
    not_exactly_arch = False

    if "little" in gdb.execute("show endian", to_string=True).lower():
        endian = "little"
    else:
        endian = "big"

    if pwndbg.proc.alive:
        arch = gdb.newest_frame().architecture().name()
    else:
        arch = gdb.execute("show architecture", to_string=True).strip()
        not_exactly_arch = True

    # Below, we fix the fetched architecture
    for match in ARCHS:
        if match in arch:
            # Distinguish between Cortex-M and other ARM
            if match == "arm" and "-m" in arch:
                match = "armcm"
            return match, ptrsize, endian

    if not_exactly_arch:
        raise RuntimeError("Could not deduce architecture from: %s" % arch)

    return arch, ptrsize, endian


def update():
    # We can't just assign to `arch` with a new `Arch` object. Modules that have
    # already imported it will still have a reference to the old `arch`
    # object. Instead, we call `__init__` again with the new args
    arch_name, ptrsize, endian = _get_arch(typeinfo.ptrsize)
    arch.__init__(arch_name, ptrsize, endian)
