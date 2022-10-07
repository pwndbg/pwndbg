import os
import re
import sys

import gdb

import pwndbg.gdblib.abi
import pwndbg.gdblib.arch
import pwndbg.gdblib.events
import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.qemu
import pwndbg.gdblib.regs
import pwndbg.gdblib.stack
import pwndbg.gdblib.typeinfo

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


AT_CONSTANTS = {
    0: "AT_NULL",  # /* End of vector */
    1: "AT_IGNORE",  # /* Entry should be ignored */
    2: "AT_EXECFD",  # /* File descriptor of program */
    3: "AT_PHDR",  # /* Program headers for program */
    4: "AT_PHENT",  # /* Size of program header entry */
    5: "AT_PHNUM",  # /* Number of program headers */
    6: "AT_PAGESZ",  # /* System page size */
    7: "AT_BASE",  # /* Base address of interpreter */
    8: "AT_FLAGS",  # /* Flags */
    9: "AT_ENTRY",  # /* Entry point of program */
    10: "AT_NOTELF",  # /* Program is not ELF */
    11: "AT_UID",  # /* Real uid */
    12: "AT_EUID",  # /* Effective uid */
    13: "AT_GID",  # /* Real gid */
    14: "AT_EGID",  # /* Effective gid */
    15: "AT_PLATFORM",  # /* String identifying platform */
    16: "AT_HWCAP",  # /* Machine dependent hints about processor capabilities */
    17: "AT_CLKTCK",  # /* Frequency of times() */
    18: "AT_FPUCW",
    19: "AT_DCACHEBSIZE",
    20: "AT_ICACHEBSIZE",
    21: "AT_UCACHEBSIZE",
    22: "AT_IGNOREPPC",
    23: "AT_SECURE",
    24: "AT_BASE_PLATFORM",  # String identifying real platforms
    25: "AT_RANDOM",  # Address of 16 random bytes
    31: "AT_EXECFN",  # Filename of executable
    32: "AT_SYSINFO",
    33: "AT_SYSINFO_EHDR",
    34: "AT_L1I_CACHESHAPE",
    35: "AT_L1D_CACHESHAPE",
    36: "AT_L2_CACHESHAPE",
    37: "AT_L3_CACHESHAPE",
}

sys.modules[__name__].__dict__.update({v: k for k, v in AT_CONSTANTS.items()})


class AUXV(dict):
    def set(self, const, value):
        name = AT_CONSTANTS.get(const, "AT_UNKNOWN%i" % const)

        if name in ["AT_EXECFN", "AT_PLATFORM"]:
            try:
                value = gdb.Value(value)
                value = value.cast(pwndbg.gdblib.typeinfo.pchar)
                value = value.string()
            except Exception:
                value = "couldnt read AUXV!"

        self[name] = value

    def __getattr__(self, attr):
        return self.get(attr)

    def __str__(self):
        return str({k: v for k, v in self.items() if v is not None})


@pwndbg.lib.memoize.reset_on_objfile
@pwndbg.lib.memoize.reset_on_start
def get():
    return use_info_auxv() or walk_stack() or AUXV()


def use_info_auxv():
    lines = pwndbg.gdblib.info.auxv().splitlines()

    if not lines:
        return None

    auxv = AUXV()
    for line in lines:
        match = re.match("([0-9]+) .*? (0x[0-9a-f]+|[0-9]+$)", line)
        if not match:
            print("Warning: Skipping auxv entry '{}'".format(line))
            continue

        const, value = int(match.group(1)), int(match.group(2), 0)
        auxv.set(const, value)

    return auxv


def find_stack_boundary(addr):
    # For real binaries, we can just use pwndbg.gdblib.memory.find_upper_boundary
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
    addr = pwndbg.lib.memory.page_align(int(addr))
    try:
        while True:
            if b"\x7fELF" == pwndbg.gdblib.memory.read(addr, 4):
                break
            addr += pwndbg.lib.memory.PAGE_SIZE
    except gdb.MemoryError:
        pass
    return addr


def walk_stack():
    if not pwndbg.gdblib.abi.linux:
        return None
    if pwndbg.gdblib.qemu.is_qemu_kernel():
        return None

    auxv = walk_stack2(0)

    if not auxv:
        # For whatever reason, sometimes the ARM AUXV under qemu-user is
        # not aligned properly.
        auxv = walk_stack2(1)

    if not auxv.get("AT_EXECFN", None):
        try:
            auxv["AT_EXECFN"] = _get_execfn()
        except gdb.MemoryError:
            pass

    return auxv


def walk_stack2(offset=0):
    sp = pwndbg.gdblib.regs.sp

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
    end = find_stack_boundary(sp)
    p = gdb.Value(end).cast(pwndbg.gdblib.typeinfo.ulong.pointer())

    p -= offset

    # So we don't walk off the end of the stack
    p -= 2

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
    while p.dereference() != 0 or (p + 1).dereference() != 0:
        p -= 2

    # Now we want to continue until we fine, at a minimum, AT_BASE.
    # While there's no guarantee that this exists, I've not ever found
    # an instance when it doesn't.
    #
    # This check is needed because the above loop isn't
    # guaranteed to actually get us to AT_NULL, just to some
    # consecutive NULLs.  QEMU is pretty generous with NULLs.
    for i in range(1024):
        if p.dereference() == AT_BASE:
            break
        p -= 2
    else:
        return AUXV()

    # If we continue to p back, we should bump into the
    # very end of ENVP (and perhaps ARGV if ENVP is empty).
    #
    # The highest value for the vector is AT_SYSINFO_EHDR, 33.
    while (p - 2).dereference() < 37:
        p -= 2

    # Scan them into our structure
    auxv = AUXV()
    while True:
        const = int((p + 0).dereference()) & pwndbg.gdblib.arch.ptrmask
        value = int((p + 1).dereference()) & pwndbg.gdblib.arch.ptrmask

        if const == AT_NULL:
            break

        auxv.set(const, value)
        p += 2

    return auxv


def _get_execfn():
    # If the stack is not sane, this won't work
    if not pwndbg.gdblib.memory.peek(pwndbg.gdblib.regs.sp):
        return

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
    addr = pwndbg.gdblib.stack.find_upper_stack_boundary(pwndbg.gdblib.regs.sp)

    while pwndbg.gdblib.memory.byte(addr - 1) == 0:
        addr -= 1

    while pwndbg.gdblib.memory.byte(addr - 1) != 0:
        addr -= 1

    v = pwndbg.gdblib.strings.get(addr, 1024)
    if v:
        return os.path.abspath(v)
