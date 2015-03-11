from __future__ import print_function
import gdb
import pwndbg.events
import pwndbg.memoize
import pwndbg.memory
import pwndbg.elf


@pwndbg.events.new_objfile
@pwndbg.memoize.reset_on_objfile
def find():
    exe = pwndbg.elf.exe()

    if not exe:
        return None

    #
    # There are two places that the link_map can be.
    #
    # - DT_DEBUG
    # - DT_PLTGOT
    #
    # This code is mostly copied from my implementation in
    # pwntools/binjitsu.  See the documentation there:
    #
    # - https://github.com/binjitsu/binjitsu/blob/master/pwnlib/dynelf.py
    #