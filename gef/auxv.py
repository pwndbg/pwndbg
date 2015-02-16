import gdb

import gef.events
import gef.info
import gef.regs
import gef.types

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
    0 : 'AT_NULL',      # /* End of vector */
    1 : 'AT_IGNORE',    # /* Entry should be ignored */
    2 : 'AT_EXECFD',    # /* File descriptor of program */
    3 : 'AT_PHDR',      # /* Program headers for program */
    4 : 'AT_PHENT',     # /* Size of program header entry */
    5 : 'AT_PHNUM',     # /* Number of program headers */
    6 : 'AT_PAGESZ',    # /* System page size */
    7 : 'AT_BASE',      # /* Base address of interpreter */
    8 : 'AT_FLAGS',     # /* Flags */
    9 : 'AT_ENTRY',     # /* Entry point of program */
    10: 'AT_NOTELF',    # /* Program is not ELF */
    11: 'AT_UID',       # /* Real uid */
    12: 'AT_EUID',      # /* Effective uid */
    13: 'AT_GID',       # /* Real gid */
    14: 'AT_EGID',      # /* Effective gid */
    15: 'AT_PLATFORM',  # /* String identifying platform */
    16: 'AT_HWCAP',     # /* Machine dependent hints about processor capabilities */
    17: 'AT_CLKTCK',    # /* Frequency of times() */
    18: 'AT_FPUCW',
    19: 'AT_DCACHEBSIZE',
    20: 'AT_ICACHEBSIZE',
    21: 'AT_UCACHEBSIZE',
    22: 'AT_IGNOREPPC',
    23: 'AT_SECURE',
    24: 'AT_BASE_PLATFORM', # String identifying real platforms
    25: 'AT_RANDOM',    # Address of 16 random bytes
    31: 'AT_EXECFN',    # Filename of executable
    32: 'AT_SYSINFO',
    33: 'AT_SYSINFO_EHDR'
}


class AUXV(object):
    def __init__(self):
        for field in AT_CONSTANTS.values():
            setattr(self, field, None)
    def set(self, const, value):
        name         = AT_CONSTANTS.get(const, "AT_UNKNOWN%i" % const)

        if name in ['AT_EXECFN', 'AT_PLATFORM']:
            value = gdb.Value(value).cast(gef.types.pchar).string()

        setattr(self, name, value)
    def __str__(self):
        rv = {}
        for attr in AT_CONSTANTS.values():
            value = getattr(self, attr)
            if value is not None:
                rv[attr] = value
        return str(rv)

@gef.memoize.reset_on_objfile
def get():
    return use_info_auxv() or walk_stack() or AUXV()

def use_info_auxv():
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

    lines = gef.info.auxv().splitlines()

    if not lines:
        return None

    auxv = AUXV()
    for line in lines:
        tokens = line.split()
        const  = int(tokens[0])

        # GDB will attempt to read strings for us, we dont want this
        if '"' in tokens[-1]: tokens.pop(-1)

        value = eval(tokens[-1])
        auxv.set(const, value)
    return auxv


def walk_stack():
    sp  = gef.regs.sp

    if not sp:
        return None

    end = gef.memory.find_upper_boundary(sp)
    p   = gdb.Value(end).cast(gef.types.ulong.pointer())

    # So we don't walk off the end of the stack
    p -= 2

    # We want to find AT_NULL, which is two ULONGs of zeroes.
    #
    # Coming up from the end of the stack, there will be a
    # marker at the end which is a ULONG of zeroes, and then
    # the ARGV and ENVP data.
    #
    # Assuming that the ARGV and ENVP data is formed normally,
    # (i.e. doesn't include 8-16 consecutive zero-length args)
    # this should land us at the *END* of AUXV, which is the
    # AT_NULL vector.
    while p.dereference() != 0 or (p+1).dereference() != 0:
        p -= 2

    # In some circumstances, e.g. on QEMU-USER, there may be
    # *multiple* sequences of NULL for no good reason I can find.
    while (p-2).dereference() == 0 and (p-1).dereference() == 0:
        p -= 2

    # We've found AT_NULL
    AT_NULL = p

    # If we continue to scan back, we should bump into the
    # very end of ENVP (and perhaps ARGV if ENVP is empty).
    #
    # The highest value for the vector is AT_SYSINFO_EHDR, 33.
    while int(p.dereference()) < 33:
        p -= 2

    # Scan them into our structure
    auxv = AUXV()
    while p < AT_NULL:
        const, value = p.dereference(), (p+1).dereference()
        const        = int(const)
        value        = int(value)
        auxv.set(const, value)
        p += 2

    return auxv
