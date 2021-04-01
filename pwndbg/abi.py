# -*- coding: utf-8 -*-
import functools

import gdb

import pwndbg.arch
import pwndbg.color.message as M


class ABI:
    """
    Encapsulates information about a calling convention.
    """
    #: List or registers which should be filled with arguments before
    #: spilling onto the stack.
    register_arguments = []

    #: Minimum alignment of the stack.
    #: The value used is min(context.bytes, stack_alignment)
    #: This is necessary as Windows x64 frames must be 32-byte aligned.
    #: "Alignment" is considered with respect to the last argument on the stack.
    arg_alignment    = 1

    #: Minimum number of stack slots used by a function call
    #: This is necessary as Windows x64 requires using 4 slots on the stack
    stack_minimum      = 0

    #: Indicates that this ABI returns to the next address on the slot
    returns            = True

    def __init__(self, regs, align, minimum):
        self.register_arguments = regs
        self.arg_alignment      = align
        self.stack_minimum      = minimum

    @staticmethod
    def default():
        return {
        (32, 'i386', 'linux'):  linux_i386,
        (64, 'x86-64', 'linux'): linux_amd64,
        (64, 'aarch64', 'linux'): linux_aarch64,
        (32, 'arm', 'linux'):   linux_arm,
        (32, 'thumb', 'linux'):   linux_arm,
        (32, 'mips', 'linux'):   linux_mips,
        (32, 'powerpc', 'linux'): linux_ppc,
        (64, 'powerpc', 'linux'): linux_ppc64,
        }[(8*pwndbg.arch.ptrsize, pwndbg.arch.current, 'linux')]

    @staticmethod
    def syscall():
        return {
        (32, 'i386', 'linux'):  linux_i386_syscall,
        (64, 'x86-64', 'linux'): linux_amd64_syscall,
        (64, 'aarch64', 'linux'): linux_aarch64_syscall,
        (32, 'arm', 'linux'):   linux_arm_syscall,
        (32, 'thumb', 'linux'):   linux_arm_syscall,
        (32, 'mips', 'linux'):   linux_mips_syscall,
        (32, 'powerpc', 'linux'): linux_ppc_syscall,
        (64, 'powerpc', 'linux'): linux_ppc64_syscall,
        }[(8*pwndbg.arch.ptrsize, pwndbg.arch.current, 'linux')]

    @staticmethod
    def sigreturn():
        return {
        (32, 'i386', 'linux'):  linux_i386_sigreturn,
        (64, 'x86-64', 'linux'): linux_amd64_sigreturn,
        (32, 'arm', 'linux'):   linux_arm_sigreturn,
        (32, 'thumb', 'linux'):   linux_arm_sigreturn,
        }[(8*pwndbg.arch.ptrsize, pwndbg.arch.current, 'linux')]

class SyscallABI(ABI):
    """
    The syscall ABI treats the syscall number as the zeroth argument,
    which must be loaded into the specified register.
    """
    def __init__(self, register_arguments, *a, **kw):
        self.syscall_register = register_arguments.pop(0)
        super(SyscallABI, self).__init__(register_arguments, *a, **kw)


class SigreturnABI(SyscallABI):
    """
    The sigreturn ABI is similar to the syscall ABI, except that
    both PC and SP are loaded from the stack.  Because of this, there
    is no 'return' slot necessary on the stack.
    """
    returns = False


linux_i386   = ABI([], 4, 0)
linux_amd64  = ABI(['rdi','rsi','rdx','rcx','r8','r9'], 8, 0)
linux_arm    = ABI(['r0', 'r1', 'r2', 'r3'], 8, 0)
linux_aarch64 = ABI(['x0', 'x1', 'x2', 'x3'], 16, 0)
linux_mips  = ABI(['$a0','$a1','$a2','$a3'], 4, 0)
linux_ppc = ABI(['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'], 4, 0)
linux_ppc64 = ABI(['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'], 8, 0)

linux_i386_syscall = SyscallABI(['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp'], 4, 0)
linux_amd64_syscall = SyscallABI(['rax','rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'],   8, 0)
linux_arm_syscall   = SyscallABI(['r7', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6'], 4, 0)
linux_aarch64_syscall   = SyscallABI(['x8', 'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6'], 16, 0)
linux_mips_syscall  = SyscallABI(['$v0', '$a0','$a1','$a2','$a3'], 4, 0)
linux_ppc_syscall = ABI(['r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9'], 4, 0)
linux_ppc64_syscall = ABI(['r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9'], 8, 0)

linux_i386_sigreturn = SigreturnABI(['eax'], 4, 0)
linux_amd64_sigreturn = SigreturnABI(['rax'], 4, 0)
linux_arm_sigreturn = SigreturnABI(['r7'], 4, 0)

# Fake ABIs used by SROP
linux_i386_srop = ABI(['eax'], 4, 0)
linux_amd64_srop = ABI(['rax'], 4, 0)
linux_arm_srop = ABI(['r7'], 4, 0)


@pwndbg.events.start
def update():
    global abi
    global linux

    # Detect current ABI of client side by 'show osabi'
    #
    # Examples of strings returned by `show osabi`:
    # 'The current OS ABI is "auto" (currently "GNU/Linux").\nThe default OS ABI is "GNU/Linux".\n'
    # 'The current OS ABI is "GNU/Linux".\nThe default OS ABI is "GNU/Linux".\n'
    # 'El actual SO ABI es «auto» (actualmente «GNU/Linux»).\nEl SO ABI predeterminado es «GNU/Linux».\n'
    # 'The current OS ABI is "auto" (currently "none")'
    #
    # As you can see, there might be GDBs with different language versions
    # and so we have to support it there too.
    # Lets assume and hope that `current osabi` is returned in first line in all languages...
    abi = gdb.execute('show osabi', to_string=True).split('\n')[0]

    # Currently we support those osabis:
    # 'GNU/Linux': linux
    # 'none': bare metal

    linux = 'GNU/Linux' in abi

    if not linux:
        msg = M.warn(
            "The bare metal debugging is enabled since gdb's osabi is '%s' which is not 'GNU/Linux'.\n"
            "Ex. the page resolving and memory de-referencing ONLY works on known pages.\n"
            "This option is based on gdb client compile arguments (by default) and will be corrected if you load an ELF with a '.note.ABI-tag' section.\n"
            "If you are debugging a program that runs on the Linux ABI, please select the correct gdb client."
            % abi
        )
        print(msg)


def LinuxOnly(default=None):
    """Create a decorator that the function will be called when ABI is Linux.
    Otherwise, return `default`.
    """
    def decorator(func):
        @functools.wraps(func)
        def caller(*args, **kwargs):
            if linux:
                return func(*args, **kwargs)
            else:
                return default
        return caller

    return decorator


# Update when starting the gdb to show warning message for non-Linux ABI user.
update()
