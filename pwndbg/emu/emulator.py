"""
Emulation assistance from Unicorn.
"""

import binascii
import re

import capstone as C
import gdb
import unicorn as U

import pwndbg.disasm
import pwndbg.emu.emulator
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs


def parse_consts(u_consts):
    """
    Unicorn "consts" is a python module consisting of a variable definition
    for each known entity. We repack it here as a dict for performance.
    """
    consts = {}
    for name in dir(u_consts):
        if name.startswith("UC_"):
            consts[name] = getattr(u_consts, name)
    return consts


# Map our internal architecture names onto Unicorn Engine's architecture types.
arch_to_UC = {
    "i386": U.UC_ARCH_X86,
    "x86-64": U.UC_ARCH_X86,
    "mips": U.UC_ARCH_MIPS,
    "sparc": U.UC_ARCH_SPARC,
    "arm": U.UC_ARCH_ARM,
    "aarch64": U.UC_ARCH_ARM64,
    # 'powerpc': U.UC_ARCH_PPC,
}

arch_to_UC_consts = {
    "i386": parse_consts(U.x86_const),
    "x86-64": parse_consts(U.x86_const),
    "mips": parse_consts(U.mips_const),
    "sparc": parse_consts(U.sparc_const),
    "arm": parse_consts(U.arm_const),
    "aarch64": parse_consts(U.arm64_const),
}

# Map our internal architecture names onto Unicorn Engine's architecture types.
arch_to_CS = {
    "i386": C.CS_ARCH_X86,
    "x86-64": C.CS_ARCH_X86,
    "mips": C.CS_ARCH_MIPS,
    "sparc": C.CS_ARCH_SPARC,
    "arm": C.CS_ARCH_ARM,
    "aarch64": C.CS_ARCH_ARM64,
    # 'powerpc': C.CS_ARCH_PPC,
}

DEBUG = False


def debug(fmt, args=()):
    if DEBUG:
        print(fmt % args)


# Until Unicorn Engine provides full information about the specific instruction
# being executed for all architectures, we must rely on Capstone to provide
# that information.
arch_to_SYSCALL = {
    U.UC_ARCH_X86: [
        C.x86_const.X86_INS_SYSCALL,
        C.x86_const.X86_INS_SYSENTER,
        C.x86_const.X86_INS_SYSEXIT,
        C.x86_const.X86_INS_SYSRET,
        C.x86_const.X86_INS_IRET,
        C.x86_const.X86_INS_IRETD,
        C.x86_const.X86_INS_IRETQ,
        C.x86_const.X86_INS_INT,
        C.x86_const.X86_INS_INT1,
        C.x86_const.X86_INS_INT3,
    ],
    U.UC_ARCH_MIPS: [C.mips_const.MIPS_INS_SYSCALL],
    U.UC_ARCH_SPARC: [C.sparc_const.SPARC_INS_T],
    U.UC_ARCH_ARM: [C.arm_const.ARM_INS_SVC],
    U.UC_ARCH_ARM64: [C.arm64_const.ARM64_INS_SVC],
    U.UC_ARCH_PPC: [C.ppc_const.PPC_INS_SC],
}

blacklisted_regs = ["ip", "cs", "ds", "es", "fs", "gs", "ss", "fsbase", "gsbase"]

"""
e = pwndbg.emu.emulator.Emulator()
e.until_jump()
"""


class Emulator:
    def __init__(self):
        self.arch = pwndbg.gdblib.arch.current

        if self.arch not in arch_to_UC:
            raise NotImplementedError("Cannot emulate code for %s" % self.arch)

        self.consts = arch_to_UC_consts[self.arch]

        # Just registers, for faster lookup
        self.const_regs = {}
        r = re.compile(r"^UC_.*_REG_(.*)$")
        for k, v in self.consts.items():
            m = r.match(k)
            if m:
                self.const_regs[m.group(1)] = v

        self.uc_mode = self.get_uc_mode()
        debug("# Instantiating Unicorn for %s", self.arch)
        debug("uc = U.Uc(%r, %r)", (arch_to_UC[self.arch], self.uc_mode))
        self.uc = U.Uc(arch_to_UC[self.arch], self.uc_mode)
        self.regs = pwndbg.gdblib.regs.current

        # Jump tracking state
        self._prev = None
        self._prev_size = None
        self._curr = None

        # Initialize the register state
        for reg in (
            list(self.regs.retaddr)
            + list(self.regs.misc)
            + list(self.regs.common)
            + list(self.regs.flags)
        ):
            enum = self.get_reg_enum(reg)

            if not reg:
                debug("# Could not set register %r", reg)
                continue

            if reg in blacklisted_regs:
                debug("Skipping blacklisted register %r", reg)
                continue
            value = getattr(pwndbg.gdblib.regs, reg)
            if None in (enum, value):
                if reg not in blacklisted_regs:
                    debug("# Could not set register %r", reg)
                continue

            # All registers are initialized to zero.
            if value == 0:
                continue

            name = "U.x86_const.UC_X86_REG_%s" % reg.upper()
            debug("uc.reg_write(%(name)s, %(value)#x)", locals())
            self.uc.reg_write(enum, value)

        # Add a hook for unmapped memory
        self.hook_add(U.UC_HOOK_MEM_UNMAPPED, self.hook_mem_invalid)

        # Always stop executing as soon as there's an interrupt.
        self.hook_add(U.UC_HOOK_INTR, self.hook_intr)

        # Map in the page that $pc is on
        self.map_page(pwndbg.gdblib.regs.pc)

        # Instruction tracing
        if DEBUG:
            self.hook_add(U.UC_HOOK_CODE, self.trace_hook)

    def __getattr__(self, name):
        reg = self.get_reg_enum(name)

        if reg:
            return self.uc.reg_read(reg)

        raise AttributeError("AttributeError: %r object has no attribute %r" % (self, name))

    def update_pc(self, pc=None):
        if pc is None:
            pc = pwndbg.gdblib.regs.pc
        self.uc.reg_write(self.get_reg_enum(self.regs.pc), pc)

    def get_uc_mode(self):
        """
        Retrieve the mode used by Unicorn for the current architecture.
        """
        arch = pwndbg.gdblib.arch.current
        mode = 0

        if arch == "armcm":
            mode |= (
                (U.UC_MODE_MCLASS | U.UC_MODE_THUMB)
                if (pwndbg.gdblib.regs.xpsr & (1 << 24))
                else U.UC_MODE_MCLASS
            )

        elif arch in ("arm", "aarch64"):
            mode |= U.UC_MODE_THUMB if (pwndbg.gdblib.regs.cpsr & (1 << 5)) else U.UC_MODE_ARM

        elif arch == "mips" and "isa32r6" in gdb.newest_frame().architecture().name():
            mode |= U.UC_MODE_MIPS32R6

        else:
            mode |= {4: U.UC_MODE_32, 8: U.UC_MODE_64}[pwndbg.gdblib.arch.ptrsize]

        if pwndbg.gdblib.arch.endian == "little":
            mode |= U.UC_MODE_LITTLE_ENDIAN
        else:
            mode |= U.UC_MODE_BIG_ENDIAN

        return mode

    def map_page(self, page):
        page = pwndbg.lib.memory.page_align(page)
        size = pwndbg.lib.memory.PAGE_SIZE

        debug("# Mapping %#x-%#x", (page, page + size))

        try:
            data = pwndbg.gdblib.memory.read(page, size)
            data = bytes(data)
        except gdb.MemoryError:
            debug("Could not map page %#x during emulation! [exception]", page)
            return False

        if not data:
            debug("Could not map page %#x during emulation! [no data]", page)
            return False

        debug("uc.mem_map(%(page)#x, %(size)#x)", locals())
        self.uc.mem_map(page, size)

        debug("# Writing %#x bytes", len(data))
        debug("uc.mem_write(%(page)#x, ...)", locals())
        self.uc.mem_write(page, data)

        return True

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        debug("# Invalid access at %#x", address)

        # Page-align the start address
        start = pwndbg.lib.memory.page_align(address)
        size = pwndbg.lib.memory.page_size_align(address + size - start)
        stop = start + size

        # Map each page with the permissions that we think it has.
        for page in range(start, stop, pwndbg.lib.memory.PAGE_SIZE):
            if not self.map_page(page):
                return False

        # Demonstrate that it's mapped
        # data = binascii.hexlify(self.uc.mem_read(address, size))
        # debug("# Memory is mapped: %#x --> %r", (address, data))

        return True

    def hook_intr(self, uc, intno, user_data):
        """
        We never want to emulate through an interrupt.  Just stop.
        """
        debug("Got an interrupt")
        self.uc.emu_stop()

    def get_reg_enum(self, reg):
        """
        Returns the Unicorn Emulator enum code for the named register.

        Also supports general registers like 'sp' and 'pc'.
        """
        if not self.regs:
            return None

        # If we're looking for an exact register ('eax', 'ebp', 'r0') then
        # we can look those up easily.
        #
        #  'eax' ==> enum
        #
        if reg in self.regs.all:
            e = self.const_regs.get(reg.upper(), None)
            if e is not None:
                return e

        # If we're looking for an abstract register which *is* accounted for,
        # we can also do an indirect lookup.
        #
        #   'pc' ==> 'eip' ==> enum
        #
        if hasattr(self.regs, reg):
            return self.get_reg_enum(getattr(self.regs, reg))

        # If we're looking for an abstract register which does not exist on
        # the RegisterSet objects, we need to do an indirect lookup.
        #
        #   'sp' ==> 'stack' ==> 'esp' ==> enum
        #
        elif reg == "sp":
            return self.get_reg_enum(self.regs.stack)

        return None

    def hook_add(self, *a, **kw):
        rv = self.uc.hook_add(*a, **kw)
        debug("%r = uc.hook_add(*%r, **%r)", (rv, a, kw))
        return rv

    def hook_del(self, *a, **kw):
        debug("uc.hook_del(*%r, **%r)", (a, kw))
        return self.uc.hook_del(*a, **kw)

    def emu_start(self, *a, **kw):
        debug("uc.emu_start(*%r, **%r)", (a, kw))
        return self.uc.emu_start(*a, **kw)

    def emu_stop(self, *a, **kw):
        debug("uc.emu_stop(*%r, **%r)", (a, kw))
        return self.uc.emu_stop(*a, **kw)

    def emulate_with_hook(self, hook, count=512):
        ident = self.hook_add(U.UC_HOOK_CODE, hook)
        try:
            self.emu_start(self.pc, 0, count=count)
        finally:
            self.hook_del(ident)

    def mem_read(self, *a, **kw):
        debug("uc.mem_read(*%r, **%r)", (a, kw))
        return self.uc.mem_read(*a, **kw)

    jump_types = {C.CS_GRP_CALL, C.CS_GRP_JUMP, C.CS_GRP_RET}

    def until_jump(self, pc=None):
        """
        Emulates instructions starting at the specified address until the
        program counter is set to an address which does not linearly follow
        the previously-emulated instruction.

        Arguments:
            pc(int): Address to start at.  If `None`, uses the current instruction.
            types(list,set): List of instruction groups to stop at.
                By default, it stops at all jumps, calls, and returns.

        Return:
            Returns a tuple containing the address of the jump instruction,
            and its target in the format (address, target).

            If emulation is forced to stop (e.g., because of a syscall or
            invalid memory access) then address is the instruction which
            could not be emulated through, and target will be None.

        Notes:
            This routine does not consider 'call $+5'
        """
        if pc is not None:
            self.update_pc(pc)

        # Set up the state.  Resetting this each time means that we will not ever
        # stop on the *current* instruction.
        self._prev = None
        self._prev_size = None
        self._curr = None

        # Add the single-step hook, start emulating, and remove the hook.
        self.emulate_with_hook(self.until_jump_hook_code)

        # We're done emulating
        return self._prev, self._curr

    def until_jump_hook_code(self, _uc, address, instruction_size, _user_data):
        # We have not emulated any instructions yet.
        if self._prev is None:
            pass

        # We have moved forward one linear instruction, no branch or the
        # branch target was the next instruction.
        elif self._prev + self._prev_size == address:
            pass

        # We have branched!
        # The previous instruction does not immediately precede this one.
        else:
            self._curr = address
            debug("%#x %#X --> %#x", (self._prev, self._prev_size, self._curr))
            self.emu_stop()
            return

        self._prev = address
        self._prev_size = instruction_size

    def until_call(self, pc=None):
        addr, target = self.until_jump(pc)

        while target and C.CS_GRP_CALL not in pwndbg.disasm.one(addr).groups:
            addr, target = self.until_jump(target)

        return addr, target

    def until_syscall(self, pc=None):
        """
        Emulates instructions starting at the specified address until the program
        counter points at a syscall instruction (int 0x80, svc, etc.).
        """
        self.until_syscall_address = None
        self.emulate_with_hook(self.until_syscall_hook_code)
        return (self.until_syscall_address, None)

    def until_syscall_hook_code(self, uc, address, size, user_data):
        data = binascii.hexlify(self.mem_read(address, size))
        debug("# Executing instruction at %(address)#x with bytes %(data)s", locals())
        self.until_syscall_address = address

    def single_step(self, pc=None):
        """Steps one instruction.

        Yields:
            Each iteration, yields a tuple of (address, instruction_size).=

            A StopIteration is raised if a fault or syscall or call instruction
            is encountered.
        """
        self._single_step = (None, None)

        pc = pc or self.pc
        insn = pwndbg.disasm.one(pc)

        # If we don't know how to disassemble, bail.
        if insn is None:
            debug("Can't disassemble instruction at %#x", pc)
            return self._single_step

        debug("# Single-stepping at %#x: %s %s", (pc, insn.mnemonic, insn.op_str))

        try:
            self.single_step_hook_hit_count = 0
            self.emulate_with_hook(self.single_step_hook_code, count=1)
        except U.unicorn.UcError as e:
            self._single_step = (None, None)

        return self._single_step

    def single_step_iter(self, pc=None):
        a = self.single_step(pc)

        while a:
            yield a
            a = self.single_step(pc)

    def single_step_hook_code(self, _uc, address, instruction_size, _user_data):
        # For whatever reason, the hook will hit twice on
        # unicorn >= 1.0.2rc4, but not on unicorn-1.0.2rc1~unicorn-1.0.2rc3,
        # So we use a counter to ensure the code run only once
        if self.single_step_hook_hit_count == 0:
            debug("# single_step: %#-8x", address)
            self._single_step = (address, instruction_size)
            self.single_step_hook_hit_count += 1

    def dumpregs(self):
        for reg in (
            list(self.regs.retaddr)
            + list(self.regs.misc)
            + list(self.regs.common)
            + list(self.regs.flags)
        ):
            enum = self.get_reg_enum(reg)

            if not reg or enum is None:
                debug("# Could not dump register %r", reg)
                continue

            name = "U.x86_const.UC_X86_REG_%s" % reg.upper()
            value = self.uc.reg_read(enum)
            debug("uc.reg_read(%(name)s) ==> %(value)x", locals())

    def trace_hook(self, _uc, address, instruction_size, _user_data):
        data = binascii.hexlify(self.mem_read(address, instruction_size))
        debug("# trace_hook: %#-8x %r", (address, data))
