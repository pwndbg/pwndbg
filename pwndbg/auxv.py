from __future__ import annotations

import os
import re
import struct
from typing import Optional

import pwndbg.aglib.arch
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.regs
import pwndbg.aglib.stack
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.config
import pwndbg.lib.memory
from pwndbg.lib.elftypes import AT_CONSTANT_NAMES
from pwndbg.lib.elftypes import AUXV

# We use `info.auxv()` when available.
if pwndbg.dbg.is_gdblib_available():
    import pwndbg.gdblib.info


auto_explore = pwndbg.config.add_param(
    "auto-explore-auxv",
    "warn",
    "Enable or disable stack exploration for AUXV information; it may be really slow.",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["warn", "yes", "no"],
)


example_info_auxv_linux = """
33   AT_SYSINFO_EHDR      System-supplied DSO's ELF header 0x7ffff7ffa000
16   AT_HWCAP             Machine-dependent CPU capability hints 0xfabfbff
6    AT_PAGESZ            System page size               4096
17   AT_CLKTCK            Frequency of times()           100
3    AT_PHDR              Program headers for program    0x400040
4    AT_PHENT             Size of program header entry   56
5    AT_PHNUM             Number of program headers      9
7    AT_BASE              Base address of interpreter    0x7ffff7dda000
8    AT_FLAGS             Flags                          0x0
9    AT_ENTRY             Entry point of program         0x42020b
11   AT_UID               Real user ID                   1000
12   AT_EUID              Effective user ID              1000
13   AT_GID               Real group ID                  1000
14   AT_EGID              Effective group ID             1000
23   AT_SECURE            Boolean, was exec setuid-like? 0
25   AT_RANDOM            Address of 16 random bytes     0x7fffffffdb39
31   AT_EXECFN            File name of executable        0x7fffffffefee "/bin/bash"
15   AT_PLATFORM          String identifying platform    0x7fffffffdb49 "x86_64"
0    AT_NULL              End of vector                  0x0
"""


@pwndbg.lib.cache.cache_until("objfile", "start")
def get() -> AUXV:
    if not pwndbg.dbg.selected_inferior().is_linux() or pwndbg.aglib.qemu.is_qemu_kernel():
        return AUXV()

    return use_info_auxv() or procfs_auxv() or explore_stack_auxv() or AUXV()


def procfs_auxv() -> AUXV | None:
    if pwndbg.aglib.arch.ptrsize == 8:
        field_format = "QQ"  # for 64bit system
    elif pwndbg.aglib.arch.ptrsize == 4:
        field_format = "II"  # for 32bit system
    else:
        assert False
    field_size = struct.calcsize(field_format)

    try:
        data = pwndbg.aglib.file.get(f"/proc/{pwndbg.aglib.proc.tid}/auxv")
    except OSError:
        return None

    if not data:
        return None

    auxv = AUXV()
    end_type = AT_CONSTANT_NAMES["AT_NULL"]
    for i in range(0, len(data), field_size):
        entry = data[i : i + field_size]

        if len(entry) < field_size:
            break  # Ignore incomplete entry at the end

        a_type, a_val = struct.unpack(field_format, entry)

        # AT_NULL indicates the end of the vector
        if a_type == end_type:
            break
        auxv.set(a_type, a_val)

    return auxv


def use_info_auxv() -> Optional[AUXV]:
    lines = None
    if pwndbg.dbg.is_gdblib_available():
        lines = pwndbg.gdblib.info.auxv().splitlines()

    if not lines:
        return None

    auxv = AUXV()
    for line in lines:
        match = re.match("([0-9]+) .*? (0x[0-9a-f]+|[0-9]+$)", line)
        if not match:
            print(f"Warning: Skipping auxv entry '{line}'")
            continue

        const, value = int(match.group(1)), int(match.group(2), 0)
        auxv.set(const, value)

    return auxv


_warn_explore_once = True


def explore_stack_auxv() -> AUXV | None:
    if auto_explore.value == "warn":
        print(
            M.warn(
                "Warning: All methods to detect AUXV have failed.\n"
                "You can explore AUXV using stack exploration, but it may be very slow.\n"
                "To explicitly explore, use the command: `auxv_explore`\n"
                "Alternatively, enable it by default with: `set auto-explore-auxv yes`\n\n"
                "Note: AUXV is probably not necessary for debugging firmware or embedded systems."
            )
        )
        return None
    elif auto_explore.value == "no":
        return None

    auxv = walk_stack2(0)

    if not auxv:
        # For whatever reason, sometimes the ARM AUXV under qemu-user is
        # not aligned properly.
        auxv = walk_stack2(1)

    if not auxv.get("AT_EXECFN", None):
        try:
            auxv["AT_EXECFN"] = _get_execfn()
        except pwndbg.dbg_mod.Error:
            pass

    return auxv


def walk_stack2(offset: int = 0) -> AUXV:
    sp = pwndbg.aglib.regs.sp

    if not sp:
        return AUXV()

    #
    # Strategy looks like this:
    #
    # 1) Find the end of the stack.
    # 2) Scan backward from the end of the stack until we find what
    #    could be an AT_NULL entry (two consecutive ULONGs)
    # 3) Scan back a little further until we find what could be an
    #   AT_ENTRY entry.
    # 4) Keep scanning back until we find something that isn't in the
    #    set of known AT_ enums.
    # 5) Vacuum up between the two.
    #
    end = _find_stack_boundary(sp)
    p = pwndbg.dbg.selected_inferior().create_value(end).cast(pwndbg.aglib.typeinfo.ulong.pointer())

    p -= offset

    # So we don't walk off the end of the stack
    p -= 2

    try:
        # Find a ~guess at where AT_NULL is.
        #
        # Coming up from the end of the stack, there will be a
        # marker at the end which is a single ULONG of zeroes, and then
        # the ARGV and ENVP data.
        #
        # Assuming that the ARGV and ENVP data is formed normally,
        # (i.e. doesn't include 8-16 consecutive zero-length args)
        # this should land us at the *END* of AUXV, which is the
        # AT_NULL vector.
        while int(p.dereference()) != 0 or int((p + 1).dereference()) != 0:
            p -= 2

        # Now we want to continue until we fine, at a minimum, AT_BASE.
        # While there's no guarantee that this exists, I've not ever found
        # an instance when it doesn't.
        #
        # This check is needed because the above loop isn't
        # guaranteed to actually get us to AT_NULL, just to some
        # consecutive NULLs.  QEMU is pretty generous with NULLs.
        for i in range(1024):
            if int(p.dereference()) == AT_CONSTANT_NAMES["AT_BASE"]:
                break
            p -= 2
        else:
            return AUXV()

        # If we continue to p back, we should bump into the
        # very end of ENVP (and perhaps ARGV if ENVP is empty).
        #
        # The highest value for the vector is AT_SYSINFO_EHDR, 33.
        while int((p - 2).dereference()) < 37:
            p -= 2

        # Scan them into our structure
        auxv = AUXV()
        while True:
            const = int((p + 0).dereference()) & pwndbg.aglib.arch.ptrmask
            value = int((p + 1).dereference()) & pwndbg.aglib.arch.ptrmask

            if const == AT_CONSTANT_NAMES["AT_NULL"]:
                break

            auxv.set(const, value)
            p += 2

        return auxv
    except pwndbg.dbg_mod.Error:
        # If SP is inaccessible or we went past through stack and haven't found AUXV
        # then return an empty AUXV...
        return AUXV()


def _find_stack_boundary(addr: int) -> int:
    # For real binaries, we can just use pwndbg.aglib.memory.find_upper_boundary
    # to search forward until we walk off the end of the stack.
    #
    # Unfortunately, qemu-user emulation likes to paste the stack right
    # before binaries in memory.  This means that we walk right past the
    # stack and to the end of some random ELF.
    #
    # In order to mitigate this, we search page-by-page until either:
    #
    # 1) We get a page fault, and stop
    # 2) We find an ELF header, and stop
    addr = pwndbg.lib.memory.page_align(addr)
    try:
        while True:
            if b"\x7fELF" == pwndbg.aglib.memory.read(addr, 4):
                break
            addr += pwndbg.lib.memory.PAGE_SIZE
    except pwndbg.dbg_mod.Error:
        pass
    return addr


def _get_execfn() -> str | None:
    # If the stack is not sane, this won't work
    if not pwndbg.aglib.memory.peek(pwndbg.aglib.regs.sp):
        return None

    # QEMU does not put AT_EXECFN in the Auxiliary Vector
    # on the stack.
    #
    # However, it does put it at the very top of the stack.
    #
    # 32c:1960|      0x7fffffffefe0 <-- '/home/user/pwndbg/ld....'
    # 32d:1968|      0x7fffffffefe8 <-- 'er/pwndbg/ld.so'
    # 32e:1970|      0x7fffffffeff0 <-- 0x6f732e646c2f67 /* 'g/ld.so' */
    # 32f:1978|      0x7fffffffeff8 <-- 0
    # 330:1980|      0x7ffffffff000
    addr = pwndbg.aglib.stack.find_upper_stack_boundary(pwndbg.aglib.regs.sp)

    while pwndbg.aglib.memory.byte(addr - 1) == 0:
        addr -= 1

    while pwndbg.aglib.memory.byte(addr - 1) != 0:
        addr -= 1

    v = pwndbg.aglib.strings.get(addr, 1024)
    if v:
        return os.path.abspath(v)
    return None
