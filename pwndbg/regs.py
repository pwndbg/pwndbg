#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Reading register value from the inferior, and provides a
standardized interface to registers like "sp" and "pc".
"""
from __future__ import print_function
import collections
import ctypes
import re
import sys
import tempfile
from types import ModuleType

import gdb
import pwndbg.arch
import pwndbg.compat
import pwndbg.events
import pwndbg.memoize
import pwndbg.proc
import pwndbg.remote

try:
    long
except NameError:
    long=int


class RegisterSet(object):
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
    flags_names = None

    #: List of native-size generalp-purpose registers
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

    def __init__(self,
                 pc='pc',
                 stack='sp',
                 frame=None,
                 retaddr=tuple(),
                 flags=tuple(),
                 flags_names=dict(),
                 gpr=tuple(),
                 misc=tuple(),
                 args=tuple(),
                 retval=None):
        self.pc    = pc
        self.stack = stack
        self.frame = frame
        self.retaddr = retaddr
        self.flags  = flags
        self.flags_names = flags_names
        self.gpr    = gpr
        self.misc   = misc
        self.args   = args
        self.retval = retval

        # In 'common', we don't want to lose the ordering of:
        self.common = []
        for reg in gpr + (frame, stack, pc) + flags:
            if reg and reg not in self.common:
                self.common.append(reg)

        self.all = set(i for i in misc) | set(flags) | set(self.common)
        self.all -= {None}

    def __iter__(self):
        for r in self.all:
            yield r

arm = RegisterSet(  retaddr = ('lr',),
                    flags   = ('cpsr',),
                    gpr     = tuple('r%i' % i for i in range(13)),
                    args    = ('r0','r1','r2','r3'),
                    retval  = 'r0')

aarch64 = RegisterSet(  retaddr = ('lr',),
                        flags   = ('cpsr',),
                        gpr     = tuple('x%i' % i for i in range(29)),
                        misc    = tuple('w%i' % i for i in range(29)),
                        args    = ('x0','x1','x2','x3'),
                        retval  = 'x0')

x86flags = {'eflags': {
     0: 'CF',
     2: 'PF',
     4: 'AF',
     6: 'ZF',
     7: 'SF',
     9: 'IF',
    10: 'DF',
    11: 'OF',
}}

amd64 = RegisterSet(pc      = 'rip',
                    stack   = 'rsp',
                    frame   = 'rbp',
                    flags   = ('eflags',),
                    flags_names = x86flags,
                    gpr     = ('rax','rbx','rcx','rdx','rdi','rsi',
                               'r8', 'r9', 'r10','r11','r12',
                               'r13','r14','r15'),
                    misc    =  ('cs','ss','ds','es','fs','gs',
                                'fsbase', 'gsbase',
                                'ax','ah','al',
                                'bx','bh','bl',
                                'cx','ch','cl',
                                'dx','dh','dl',
                                'dil','sil','spl','bpl',
                                'di','si','bp','sp','ip'),
                    args    =  ('rdi','rsi','rdx','rcx','r8','r9'),
                    retval  = 'rax')

i386 = RegisterSet( pc      = 'eip',
                    stack   = 'esp',
                    frame   = 'ebp',
                    flags   = ('eflags',),
                    gpr     = ('eax','ebx','ecx','edx','edi','esi'),
                    misc    =  ('cs','ss','ds','es','fs','gs',
                                'fsbase', 'gsbase',
                                'ax','ah','al',
                                'bx','bh','bl',
                                'cx','ch','cl',
                                'dx','dh','dl',
                                'dil','sil','spl','bpl',
                                'di','si','bp','sp','ip'),
                    retval  = 'eax')


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
powerpc = RegisterSet(  retaddr = ('lr','r0'),
                        flags   = ('msr','xer'),
                        gpr     = tuple('r%i' % i for i in range(3,32)),
                        misc    = ('cr','lr','r2'),
                        args    = tuple('r%i' for i in range(3,11)),
                        retval  = 'r3')

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
sparc = RegisterSet(stack   = 'o6',
                    frame   = 'i6',
                    retaddr = ('o7',),
                    flags   = ('psr',),
                    gpr     = sparc_gp,
                    args    = ('i0','i1','i2','i3','i4','i5'),
                    retval  = 'o0')


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
mips = RegisterSet( frame   = 'fp',
                    retaddr = ('ra',),
                    gpr     = ('v0','v1','a0','a1','a2','a3') \
                              + tuple('t%i' % i for i in range(10)) \
                              + tuple('s%i' % i for i in range(9)),
                    args    = ('a0','a1','a2','a3'),
                    retval  = 'v0')

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

@pwndbg.proc.OnlyWhenRunning
def gdb77_get_register(name):
    return gdb.parse_and_eval('$' + name)

@pwndbg.proc.OnlyWhenRunning
def gdb79_get_register(name):
    return gdb.newest_frame().read_register(name)

try:
    gdb.Frame.read_register
    get_register = gdb79_get_register
except AttributeError:
    get_register = gdb77_get_register


# We need to manually make some ptrace calls to get fs/gs bases on Intel
PTRACE_ARCH_PRCTL = 30
ARCH_GET_FS = 0x1003
ARCH_GET_GS = 0x1004

class module(ModuleType):
    last = {}

    @pwndbg.memoize.reset_on_stop
    def __getattr__(self, attr):
        attr = attr.lstrip('$')
        try:
            # Seriously, gdb? Only accepts uint32.
            if 'eflags' in attr:
                value = gdb77_get_register(attr)
                value = value.cast(pwndbg.typeinfo.uint32)
            else:
                value = get_register(attr)
                value = value.cast(pwndbg.typeinfo.ptrdiff)

            value = int(value)
            return value & pwndbg.arch.ptrmask
        except (ValueError, gdb.error):
            return None

    @pwndbg.memoize.reset_on_stop
    def __getitem__(self, item):
        if isinstance(item, int):
            return arch_to_regs[pwndbg.arch.current][item]

        if not isinstance(item, pwndbg.compat.basestring):
            print("Unknown register type: %r" % (item))
            import pdb, traceback
            traceback.print_stack()
            pdb.set_trace()
            return None

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
    def common(self):
        return arch_to_regs[pwndbg.arch.current].common

    @property
    def frame(self):
        return arch_to_regs[pwndbg.arch.current].frame

    @property
    def retaddr(self):
        return arch_to_regs[pwndbg.arch.current].retaddr

    @property
    def flags(self):
        return arch_to_regs[pwndbg.arch.current].flags

    @property
    def flags_names(self):
        return arch_to_regs[pwndbg.arch.current].flags_names

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

    def describe_flags(self, reg):
        flags = []
        names = self.flags_names

        if not names or reg not in names:
            return

        value = self[reg]
        for bit, name in sorted(names[reg].items()):
            isset = value & (2<<bit)
            yield name, isset

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

    @property
    @pwndbg.memoize.reset_on_stop
    def fsbase(self):
        return self._fs_gs_helper(ARCH_GET_FS)

    @property
    @pwndbg.memoize.reset_on_stop
    def gsbase(self):
        return self._fs_gs_helper(ARCH_GET_GS)

    def _fs_gs_helper(self, which):
        """Supports fetching based on segmented addressing, a la fs:[0x30].

        Requires ptrace'ing the child directly."""

        # We can't really do anything if the process is remote.
        if pwndbg.remote.is_remote(): return 0

        # Use the lightweight process ID
        pid, lwpid, tid = gdb.selected_thread().ptid

        # Get the register
        ppvoid = ctypes.POINTER(ctypes.c_void_p)
        value  = ppvoid(ctypes.c_void_p())
        value.contents.value = 0

        libc  = ctypes.CDLL('libc.so.6')
        result = libc.ptrace(PTRACE_ARCH_PRCTL,
                             lwpid,
                             value,
                             which)

        if result == 0:
            return (value.contents.value or 0) & pwndbg.arch.ptrmask

        return 0

    def __repr__(self):
        return ('<module pwndbg.regs>')

# To prevent garbage collection
tether = sys.modules[__name__]
sys.modules[__name__] = module(__name__, '')


@pwndbg.events.cont
def update_last():
    M = sys.modules[__name__]
    M.last = {k:M[k] for k in M.common}
