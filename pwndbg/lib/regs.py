"""
Reading register value from the inferior, and provides a
standardized interface to registers like "sp" and "pc".
"""
import collections


class RegisterSet:
    #: Program counter register
    pc = None

    #: Stack pointer register
    stack = None

    #: Frame pointer register
    frame = None

    #: Return address register
    retaddr = None

    #: Flags register (eflags, cpsr)
    flags = None

    #: List of native-size general-purpose registers
    gpr = None

    #: List of miscellaneous, valid registers
    misc = None

    #: Register-based arguments for most common ABI
    regs = None

    #: Return value register
    retval = None

    #: Common registers which should be displayed in the register context
    common = None

    #: All valid registers
    all = None

    def __init__(
        self,
        pc="pc",
        stack="sp",
        frame=None,
        retaddr=tuple(),
        flags=dict(),
        gpr=tuple(),
        misc=tuple(),
        args=tuple(),
        retval=None,
    ):
        self.pc = pc
        self.stack = stack
        self.frame = frame
        self.retaddr = retaddr
        self.flags = flags
        self.gpr = gpr
        self.misc = misc
        self.args = args
        self.retval = retval

        # In 'common', we don't want to lose the ordering of:
        self.common = []
        for reg in gpr + (frame, stack, pc) + tuple(flags):
            if reg and reg not in self.common:
                self.common.append(reg)

        self.all = set(i for i in misc) | set(flags) | set(self.retaddr) | set(self.common)
        self.all -= {None}

    def __iter__(self):
        for r in self.all:
            yield r


arm_cpsr_flags = collections.OrderedDict(
    [
        ("N", 31),
        ("Z", 30),
        ("C", 29),
        ("V", 28),
        ("Q", 27),
        ("J", 24),
        ("T", 5),
        ("E", 9),
        ("A", 8),
        ("I", 7),
        ("F", 6),
    ]
)
arm_xpsr_flags = collections.OrderedDict(
    [("N", 31), ("Z", 30), ("C", 29), ("V", 28), ("Q", 27), ("T", 24)]
)

arm = RegisterSet(
    retaddr=("lr",),
    flags={"cpsr": arm_cpsr_flags},
    gpr=("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"),
    args=("r0", "r1", "r2", "r3"),
    retval="r0",
)

# ARM Cortex-M
armcm = RegisterSet(
    retaddr=("lr",),
    flags={"xpsr": arm_xpsr_flags},
    gpr=("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"),
    args=("r0", "r1", "r2", "r3"),
    retval="r0",
)

# FIXME AArch64 does not have a CPSR register
aarch64 = RegisterSet(
    retaddr=("lr",),
    flags={"cpsr": {}},
    # X29 is the frame pointer register (FP) but setting it
    # as frame here messes up the register order to the point
    # it's confusing. Think about improving this if frame
    # pointer semantics are required for other functionalities.
    # frame   = 'x29',
    gpr=(
        "x0",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
        "x8",
        "x9",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17",
        "x18",
        "x19",
        "x20",
        "x21",
        "x22",
        "x23",
        "x24",
        "x25",
        "x26",
        "x27",
        "x28",
        "x29",
        "x30",
    ),
    misc=(
        "w0",
        "w1",
        "w2",
        "w3",
        "w4",
        "w5",
        "w6",
        "w7",
        "w8",
        "w9",
        "w10",
        "w11",
        "w12",
        "w13",
        "w14",
        "w15",
        "w16",
        "w17",
        "w18",
        "w19",
        "w20",
        "w21",
        "w22",
        "w23",
        "w24",
        "w25",
        "w26",
        "w27",
        "w28",
    ),
    args=("x0", "x1", "x2", "x3"),
    retval="x0",
)

x86flags = {
    "eflags": collections.OrderedDict(
        [("CF", 0), ("PF", 2), ("AF", 4), ("ZF", 6), ("SF", 7), ("IF", 9), ("DF", 10), ("OF", 11)]
    )
}

amd64 = RegisterSet(
    pc="rip",
    stack="rsp",
    frame="rbp",
    flags=x86flags,
    gpr=(
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rdi",
        "rsi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ),
    misc=(
        "cs",
        "ss",
        "ds",
        "es",
        "fs",
        "gs",
        "fsbase",
        "gsbase",
        "ax",
        "ah",
        "al",
        "bx",
        "bh",
        "bl",
        "cx",
        "ch",
        "cl",
        "dx",
        "dh",
        "dl",
        "dil",
        "sil",
        "spl",
        "bpl",
        "di",
        "si",
        "bp",
        "sp",
        "ip",
    ),
    args=("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    retval="rax",
)

i386 = RegisterSet(
    pc="eip",
    stack="esp",
    frame="ebp",
    flags=x86flags,
    gpr=("eax", "ebx", "ecx", "edx", "edi", "esi"),
    misc=(
        "cs",
        "ss",
        "ds",
        "es",
        "fs",
        "gs",
        "fsbase",
        "gsbase",
        "ax",
        "ah",
        "al",
        "bx",
        "bh",
        "bl",
        "cx",
        "ch",
        "cl",
        "dx",
        "dh",
        "dl",
        "di",
        "si",
        "bp",
        "sp",
        "ip",
    ),
    retval="eax",
)

# http://math-atlas.sourceforge.net/devel/assembly/elfspec_ppc.pdf
# r0      Volatile register which may be modified during function linkage
# r1      Stack frame pointer, always valid
# r2      System-reserved register (points at GOT)
# r3-r4   Volatile registers used for parameter passing and return values
# r5-r10  Volatile registers used for parameter passing
# r11-r12 Volatile registers which may be modified during function linkage
# r13     Small data area pointer register (points to TLS)
# r14-r30 Registers used for local variables
# r31     Used for local variables or "environment pointers"
powerpc = RegisterSet(
    retaddr=("lr",),
    flags={"msr": {}, "xer": {}},
    gpr=(
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "r16",
        "r17",
        "r18",
        "r19",
        "r20",
        "r21",
        "r22",
        "r23",
        "r24",
        "r25",
        "r26",
        "r27",
        "r28",
        "r29",
        "r30",
        "r31",
        "cr",
        "ctr",
    ),
    args=("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
    retval="r3",
)

# http://people.cs.clemson.edu/~mark/sparc/sparc_arch_desc.txt
# http://people.cs.clemson.edu/~mark/subroutines/sparc.html
# https://www.utdallas.edu/~edsha/security/sparcoverflow.htm
#
# http://people.cs.clemson.edu/~mark/sparc/assembly.txt
# ____________________________________
# %g0 == %r0  (always zero)           \
# %g1 == %r1                          | g stands for global
# ...                                 |
# %g7 == %r7                          |
# ____________________________________/
# %o0 == %r8                          \
# ...                                 | o stands for output (note: not 0)
# %o6 == %r14 == %sp (stack ptr)      |
# %o7 == %r15 == for return address   |
# ____________________________________/
# %l0 == %r16                         \
# ...                                 | l stands for local (note: not 1)
# %l7 == %r23                         |
# ____________________________________/
# %i0 == %r24                         \
# ...                                 | i stands for input
# %i6 == %r30 == %fp (frame ptr)      |
# %i7 == %r31 == for return address   |
# ____________________________________/

sparc = RegisterSet(
    stack="sp",
    frame="fp",
    retaddr=("i7",),
    flags={"psr": {}},
    gpr=(
        "g1",
        "g2",
        "g3",
        "g4",
        "g5",
        "g6",
        "g7",
        "o0",
        "o1",
        "o2",
        "o3",
        "o4",
        "o5",
        "o7",
        "l0",
        "l1",
        "l2",
        "l3",
        "l4",
        "l5",
        "l6",
        "l7",
        "i0",
        "i1",
        "i2",
        "i3",
        "i4",
        "i5",
    ),
    args=("i0", "i1", "i2", "i3", "i4", "i5"),
    retval="o0",
)

# http://logos.cs.uic.edu/366/notes/mips%20quick%20tutorial.htm
# r0        => zero
# r1        => temporary
# r2-r3     => values
# r4-r7     => arguments
# r8-r15    => temporary
# r16-r23   => saved values
# r24-r25   => temporary
# r26-r27   => interrupt/trap handler
# r28       => global pointer
# r29       => stack pointer
# r30       => frame pointer
# r31       => return address
mips = RegisterSet(
    frame="fp",
    retaddr=("ra",),
    gpr=(
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "t8",
        "t9",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "s8",
        "gp",
    ),
    args=("a0", "a1", "a2", "a3"),
    retval="v0",
)

reg_sets = {
    "i386": i386,
    "i8086": i386,
    "x86-64": amd64,
    "mips": mips,
    "sparc": sparc,
    "arm": arm,
    "armcm": armcm,
    "aarch64": aarch64,
    "powerpc": powerpc,
}
