#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Reading register value from the inferior, and provides a
standardized interface to registers like "sp" and "pc".
"""
import re
import sys
from types import ModuleType

import gdb
import pwndbg.arch
import pwndbg.events
import pwndbg.memoize


class RegisterSet(object):
    def __init__(self, pc, stack, frame, retaddr, flags, gpr, misc, args, retval):
        self.pc = pc
        self.stack = stack
        self.frame = frame
        self.retaddr = retaddr
        self.flags = flags
        self.gpr   = gpr
        self.misc  = misc
        self.args  = args
        self.retval = retval

        self.common = set(i for i in gpr + (frame, stack, pc) if i)
        self.all    = set(i for i in misc or tuple()) | set(flags or tuple()) | self.common

        self.common -= {None}
        self.all    -= {None}

    def __iter__(self):
        for r in self.all:
            yield r

arm = RegisterSet(  'pc',
                    'sp',
                    None,
                    ('lr',),
                    ('cpsr',),
                    ('r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12'),
                    tuple(),
                    ('r0','r1','r2','r3'),
                    'r0')

aarch64 = RegisterSet('pc',
                    'sp',
                    None,
                    ('lr',),
                    ('cpsr',),
                    ('x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12'),
                    tuple(),
                    ('x0','x1','x2','x3'),
                    'x0')


amd64 = RegisterSet('rip',
                    'rsp',
                    'rbp',
                    tuple(),
                    ('eflags',),
                    ('rax','rbx','rcx','rdx','rdi','rsi',
                     'r8', 'r9', 'r10','r11','r12',
                     'r13','r14','r15'),
                    ('cs','ss','ds','es','fs','gs'),
                    ('rdi','rsi','rdx','rcx','r8','r9'),
                    'rax')

i386 = RegisterSet('eip',
                    'esp',
                    'ebp',
                    tuple(),
                    ('eflags',),
                    ('eax','ebx','ecx','edx','edi','esi'),
                    ('cs','ss','ds','es','fs','gs'),
                    ('*((void**)$sp+0)',
                     '*((void**)$sp+1)',
                     '*((void**)$sp+2)',
                     '*((void**)$sp+3)',
                     '*((void**)$sp+4)',
                     '*((void**)$sp+5)',
                     '*((void**)$sp+6)',),
                    'eax')


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
powerpc = RegisterSet('pc',
                      'sp',
                      None,
                      ('lr','r0'),
                      ('msr','xer'),
                      tuple('r%i' % i for i in range(3,32)),
                      ('cr','lr','r2'),
                      tuple(),
                      'r3')

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

sparc_gp = tuple(['g%i' % i for i in range(1,8)]
                +['o%i' % i for i in range(0,6)]
                +['l%i' % i for i in range(0,8)]
                +['i%i' % i for i in range(0,6)])
sparc = RegisterSet('pc',
                    'o6',
                    'i6',
                    ('o7',),
                    ('psr',),
                    sparc_gp,
                    tuple(),
                    ('i0','i1','i2','i3','i4','i5'),
                    'o0')


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
mips = RegisterSet( 'pc',
                    'sp',
                    'fp',
                    ('ra',),
                    tuple(),
                    ('v0','v1','a0','a1','a2','a3') \
                    + tuple('t%i' % i for i in range(10)) \
                    + tuple('s%i' % i for i in range(9)),
                    tuple(),
                    ('a0','a1','a2','a3'),
                    'v0')

arch_to_regs = {
    'i386': i386,
    'x86-64': amd64,
    'mips': mips,
    'sparc': sparc,
    'arm': arm,
    'aarch64': aarch64,
    'powerpc': powerpc,
    'powerpc': powerpc,
}


class module(ModuleType):
    last = {}

    def __getattr__(self, attr):
        try:
            value = int(gdb.parse_and_eval('$' + attr.lstrip('$')))
            return value & pwndbg.arch.ptrmask
        except gdb.error:
            return None

    def __getitem__(self, item):
        if isinstance(item, int):
            return arch_to_regs[pwndbg.arch.current][item]

        assert isinstance(item, str), "Unknown type %r" % item

        # e.g. if we're looking for register "$rax", turn it into "rax"
        item = item.lstrip('$')
        item = getattr(self, item.lower())

        if isinstance(item, (int,long)):
            return int(item) & pwndbg.arch.ptrmask

        return item

    def __iter__(self):
        regs = set(arch_to_regs[pwndbg.arch.current]) | set(['pc','sp'])
        for item in regs:
            yield item

    @property
    def current(self):
        return arch_to_regs[pwndbg.arch.current]

    @property
    def gpr(self):
        return arch_to_regs[pwndbg.arch.current].gpr

    @property
    def frame(self):
        return arch_to_regs[pwndbg.arch.current].frame

    @property
    def retaddr(self):
        return arch_to_regs[pwndbg.arch.current].retaddr

    @property
    def stack(self):
        return arch_to_regs[pwndbg.arch.current].stack

    @property
    def retval(self):
        return arch_to_regs[pwndbg.arch.current].retval

    @property
    def all(self):
        regs = arch_to_regs[pwndbg.arch.current]
        retval = []
        for regset in (regs.pc, regs.stack, regs.frame, regs.retaddr, regs.flags, regs.gpr, regs.misc):
            if regset is None:
                continue
            elif isinstance(regset, (list, tuple)):
                retval.extend(regset)
            else:
                retval.append(regset)
        return retval

    def fix(self, expression):
        for regname in set(self.all + ['sp','pc']):
            expression = re.sub(r'\$?\b%s\b' % regname, r'$'+regname, expression)
        return expression

    def items(self):
        for regname in self.all:
            yield regname, self[regname]

    @property
    def arguments(self):
        argnames = arch_to_regs[pwndbg.arch.current].args
        retval   = []
        for arg in argnames:
            val = self[arg]
            if val is None:
                try:    val = gdb.parse_and_eval(arg)
                except: val = '???'
            retval.append(val)
        return retval

    arch_to_regs = arch_to_regs

    @property
    def changed(self):
        delta = []
        for reg, value in self.last.items():
            if self[reg] != value:
                delta.append(reg)
        return delta

# To prevent garbage collection
tether = sys.modules[__name__]
sys.modules[__name__] = module(__name__, '')


@pwndbg.events.cont
def update_last():
    M = sys.modules[__name__]
    M.last = {k:M[k] for k in M}
