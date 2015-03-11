import gdb
import sys
import re
from types import ModuleType

import pwndbg.memoize
import pwndbg.arch
class RegisterSet(object):
    def __init__(self, pc, stack, frame, retaddr, flags, gpr, misc, args):
        self.pc = pc
        self.stack = stack
        self.frame = frame
        self.retaddr = retaddr
        self.flags = flags
        self.gpr   = gpr
        self.misc  = misc
        self.args  = args

arm = RegisterSet('pc',
                  'sp',
                  None,
                  ('lr',),
                  ('cpsr',),
                  ('r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12'),
                  None,
                  ('r0','r1','r2','r3'))

aarch64 = RegisterSet('pc',
                  'sp',
                  None,
                  ('lr',),
                  ('cpsr',),
                  ('x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12'),
                  None,
                  ('x0','x1','x2','x3'))


amd64 = RegisterSet('rip',
                    'rsp',
                    'rbp',
                    None,
                    ('eflags',),
                    ('rax','rbx','rcx','rdx','rdi','rsi',
                     'r8', 'r9', 'r10','r11','r12',
                     'r13','r14','r15'),
                    ('cs','ss','ds','es','fs','gs'),
                    ('rdi','rsi','rdx','rcx','r8','r9'))

i386 = RegisterSet('eip',
                    'esp',
                    'ebp',
                    None,
                    ('eflags',),
                    ('eax','ebx','ecx','edx','edi','esi'),
                    ('cs','ss','ds','es','fs','gs'),
                    ('*((void**)$sp+0)',
                     '*((void**)$sp+1)',
                     '*((void**)$sp+2)',
                     '*((void**)$sp+3)',
                     '*((void**)$sp+4)',
                     '*((void**)$sp+5)',
                     '*((void**)$sp+6)',))


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
                      'r1',
                      ('lr','r0'),
                      ('msr','xer'),
                      tuple('r%i' % i for i in range(3,32)),
                      ('cr','lr','r2'),
                      tuple())

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
                    None,
                    ('i0','i1','i2','i3','i4','i5'))


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
mips = RegisterSet('pc',
                   'sp',
                   'fp',
                   ('ra',),
                   None,
                   tuple('r%i' % i for i in range(1,26)),
                   None,
                   ('a0','a1','a2','a3'))

arch_to_regs = {
    'i386': i386,
    'i386:x86-64': amd64,
    'mips': mips,
    'sparc': sparc,
    'arm': arm,
    'aarch64': aarch64,
    'powerpc:403': powerpc,
    'powerpc:common64': powerpc,
}


class module(ModuleType):
    def __getattr__(self, attr):
        try:
            value = int(gdb.parse_and_eval('$' + attr.lstrip('$')))
            return value & pwndbg.arch.ptrmask
        except gdb.error:
            return None

    def __getitem__(self, item):
        return getattr(self, item)

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



# To prevent garbage collection
tether = sys.modules[__name__]
sys.modules[__name__] = module(__name__, '')