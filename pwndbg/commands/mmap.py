from __future__ import annotations

import argparse

import pwndbg.aglib
import pwndbg.aglib.shellcode
import pwndbg.aglib.vmmap
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.lib.errnum
import pwndbg.lib.memory
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib import mmap as mutils

SYSCALL = "SYS_mmap"

parser = argparse.ArgumentParser(
    description="""
Calls the mmap syscall and prints its resulting address.

Note that the mmap syscall may fail for various reasons
(see `man mmap`) and, in case of failure, its return value
will not be a valid pointer.

PROT values: NONE (0), READ (1), WRITE (2), EXEC (4)

MAP values: SHARED (1), PRIVATE (2), SHARED_VALIDATE (3), FIXED (0x10),
            ANONYMOUS (0x20)

Flags and protection values can be either a string containing the names of the
flags or permissions or a single number corresponding to the bitwise OR of the
protection and flag numbers.
""",
)
parser.add_argument(
    "addr", help="Address hint to be given to mmap.", type=pwndbg.commands.sloppy_gdb_parse
)
parser.add_argument(
    "length",
    help="Length of the mapping, in bytes. Needs to be greater than zero.",
    type=int,
)
parser.add_argument(
    "prot",
    help='Prot enum or int as in mmap(2). Eg. "PROT_READ|PROT_EXEC" or 7 (for RWX).',
    type=mutils.prot_from_string,
    nargs="?",
    default=7,
)
parser.add_argument(
    "flags",
    help='Flags enum or int as in mmap(2). Eg. "MAP_PRIVATE|MAP_ANONYMOUS" or 0x22.',
    type=mutils.flag_from_string,
    nargs="?",
    default=0x22,
)
parser.add_argument(
    "fd",
    help="File descriptor of the file to be mapped, or -1 if using MAP_ANONYMOUS.",
    type=int,
    nargs="?",
    default=-1,
)
parser.add_argument(
    "offset",
    help="Offset from the start of the file, in bytes, if using file based mapping.",
    type=int,
    nargs="?",
    default=0,
)
parser.add_argument(
    "--quiet", "-q", help="Disable address validity warnings and hints", action="store_true"
)
parser.add_argument(
    "--force", "-f", help="Force potentially unsafe actions to happen", action="store_true"
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MEMORY,
    examples="""
mmap 0x0 4096 PROT_READ|PROT_WRITE|PROT_EXEC MAP_PRIVATE|MAP_ANONYMOUS -1 0
 - Maps a new private+anonymous page with RWX permissions at a location
   decided by the kernel.

mmap 0x0 4096 PROT_READ MAP_PRIVATE 10 0
 - Maps 4096 bytes of the file pointed to by file descriptor number 10 with
   read permission at a location decided by the kernel.

mmap 0xdeadbeef 0x1000
 - Maps a new private+anonymous page with RWX permissions at a page boundary
   near 0xdeadbeef.
""",
)
@pwndbg.commands.OnlyWhenRunning
def mmap(addr, length, prot=7, flags=0x22, fd=-1, offset=0, quiet=False, force=False) -> None:
    aligned_addr = int(pwndbg.lib.memory.page_align(addr))
    if flags & mutils.FLAG_DICT["MAP_FIXED"] != 0:
        # When using MAP_FIXED, it's only safe to call mmap(2) when the address
        # overlaps no other maps. We want to make sure that, unless the user
        # _really_ knows what they're doing, this call will be safe.
        #
        # Additionally, it's nice to highlight cases where the call is likely
        # to fail because the address is not properly aligned.
        addr = int(addr)
        if addr != aligned_addr and not quiet:
            print(
                message.warn(
                    f"""\
Address {addr:#x} is not properly aligned. Calling mmap with MAP_FIXED and an
unaligned address is likely to fail. Consider using the address {aligned_addr:#x}
instead.\
"""
                )
            )

        # Collision checking can get expensive for some combinations of number
        # of existing mappings and size of maps. If the user is using `--force`,
        # it's fair to assume they know what they're doing enough that we don't
        # need to bother them with any of this information, and get a nice
        # speedup as a bonus.
        if not force:
            page = pwndbg.lib.memory.Page(addr, int(length), 0, 0, pwndbg.aglib.arch.ptrsize)
            collisions = []
            vm = pwndbg.aglib.vmmap.get()

            # FIXME: The ends of the maps are sorted. We could bisect the array
            # in order to quickly reject all of the items we could never hit
            # (all of those such that `vm[i].end < page.start`).
            #
            # The target Python version as of the writing (3.8) does not support
            # `bissect.bissect_left(key=*)`, and cooking up our own
            # implementation feels overkill for something that could just be
            # fixed later with a version bump.
            for i in range(len(vm)):
                cand = vm[i]
                if cand.end > page.start and cand.start < page.end:
                    collisions.append(cand)
                if cand.start >= page.end:
                    # No more collisions are possible.
                    break

            if len(collisions) > 0:
                m = message.error
                print(
                    m(
                        f"""\
Trying to mmap with MAP_FIXED for an address range that collides with {len(collisions)}
existing range{"s" if len(collisions) > 1 else ""}:\
"""
                    )
                )
                for c in collisions:
                    print(m(f"    {c}"))
                print(
                    m(
                        """
This operation is destructive and will delete all of the listed mappings.\
"""
                    )
                )
                print(
                    m(
                        "Run this command again with `--force` if you still \
wish to proceed."
                    )
                )
                return

    elif int(addr) != aligned_addr and not quiet:
        # Highlight to the user that the address they've specified is likely to
        # be changed by the kernel.
        print(
            message.warn(
                f"""\
Address {addr:#x} is not properly aligned. It is likely to be changed to an
aligned address by the kernel automatically. If this is not desired, consider
using the address {aligned_addr:#x} instead.\
"""
            )
        )

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        pointer = await pwndbg.aglib.shellcode.exec_syscall(
            ec,
            SYSCALL,
            int(pwndbg.lib.memory.page_align(addr)),
            int(length),
            prot,
            flags,
            int(fd),
            int(offset),
        )

        pwndbg.lib.errnum.handle_syscall_ret(SYSCALL, pointer, pwndbg.aglib.arch.ptrbits)

        if pwndbg.aglib.vmmap.cache_status_text() is not None:
            print(
                message.warn(
                    "vmmap cache is on and was not cleared; "
                    "run `vmmap --refresh` to pick up the new mapping."
                )
            )

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)
