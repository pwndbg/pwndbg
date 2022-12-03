from typing import List

import pwndbg.gdblib.arch


class ABI:
    """
    Encapsulates information about a calling convention.
    """

    #: List or registers which should be filled with arguments before
    #: spilling onto the stack.
    register_arguments: List[str] = []

    #: Minimum alignment of the stack.
    #: The value used is min(context.bytes, stack_alignment)
    #: This is necessary as Windows x64 frames must be 32-byte aligned.
    #: "Alignment" is considered with respect to the last argument on the stack.
    arg_alignment = 1

    #: Minimum number of stack slots used by a function call
    #: This is necessary as Windows x64 requires using 4 slots on the stack
    stack_minimum = 0

    #: Indicates that this ABI returns to the next address on the slot
    returns = True

    def __init__(self, regs, align, minimum):
        self.register_arguments = regs
        self.arg_alignment = align
        self.stack_minimum = minimum

    @staticmethod
    def default():  # type: () -> ABI
        return DEFAULT_ABIS[(8 * pwndbg.gdblib.arch.ptrsize, pwndbg.gdblib.arch.current, "linux")]

    @staticmethod
    def syscall():  # type: () -> ABI
        return SYSCALL_ABIS[(8 * pwndbg.gdblib.arch.ptrsize, pwndbg.gdblib.arch.current, "linux")]

    @staticmethod
    def sigreturn():  # type: () -> SigreturnABI
        return SIGRETURN_ABIS[(8 * pwndbg.gdblib.arch.ptrsize, pwndbg.gdblib.arch.current, "linux")]


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


linux_i386 = ABI([], 4, 0)
linux_amd64 = ABI(["rdi", "rsi", "rdx", "rcx", "r8", "r9"], 8, 0)
linux_arm = ABI(["r0", "r1", "r2", "r3"], 8, 0)
linux_aarch64 = ABI(["x0", "x1", "x2", "x3"], 16, 0)
linux_mips = ABI(["$a0", "$a1", "$a2", "$a3"], 4, 0)
linux_ppc = ABI(["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"], 4, 0)
linux_ppc64 = ABI(["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"], 8, 0)

linux_i386_syscall = SyscallABI(["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"], 4, 0)
linux_amd64_syscall = SyscallABI(["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"], 8, 0)
linux_arm_syscall = SyscallABI(["r7", "r0", "r1", "r2", "r3", "r4", "r5", "r6"], 4, 0)
linux_aarch64_syscall = SyscallABI(["x8", "x0", "x1", "x2", "x3", "x4", "x5", "x6"], 16, 0)
linux_mips_syscall = SyscallABI(["$v0", "$a0", "$a1", "$a2", "$a3"], 4, 0)
linux_ppc_syscall = ABI(["r0", "r3", "r4", "r5", "r6", "r7", "r8", "r9"], 4, 0)
linux_ppc64_syscall = ABI(["r0", "r3", "r4", "r5", "r6", "r7", "r8", "r9"], 8, 0)

linux_i386_sigreturn = SigreturnABI(["eax"], 4, 0)
linux_amd64_sigreturn = SigreturnABI(["rax"], 4, 0)
linux_arm_sigreturn = SigreturnABI(["r7"], 4, 0)

# Fake ABIs used by SROP
linux_i386_srop = ABI(["eax"], 4, 0)
linux_amd64_srop = ABI(["rax"], 4, 0)
linux_arm_srop = ABI(["r7"], 4, 0)

DEFAULT_ABIS = {
    (32, "i386", "linux"): linux_i386,
    (64, "x86-64", "linux"): linux_amd64,
    (64, "aarch64", "linux"): linux_aarch64,
    (32, "arm", "linux"): linux_arm,
    (32, "thumb", "linux"): linux_arm,
    (32, "mips", "linux"): linux_mips,
    (32, "powerpc", "linux"): linux_ppc,
    (64, "powerpc", "linux"): linux_ppc64,
}

SYSCALL_ABIS = {
    (32, "i386", "linux"): linux_i386_syscall,
    (64, "x86-64", "linux"): linux_amd64_syscall,
    (64, "aarch64", "linux"): linux_aarch64_syscall,
    (32, "arm", "linux"): linux_arm_syscall,
    (32, "thumb", "linux"): linux_arm_syscall,
    (32, "mips", "linux"): linux_mips_syscall,
    (32, "powerpc", "linux"): linux_ppc_syscall,
    (64, "powerpc", "linux"): linux_ppc64_syscall,
}

SIGRETURN_ABIS = {
    (32, "i386", "linux"): linux_i386_sigreturn,
    (64, "x86-64", "linux"): linux_amd64_sigreturn,
    (32, "arm", "linux"): linux_arm_sigreturn,
    (32, "thumb", "linux"): linux_arm_sigreturn,
}
