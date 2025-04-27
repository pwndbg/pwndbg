"""
Emulation assistance from Unicorn.
"""

from __future__ import annotations

import binascii
import re
import string
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Tuple

import capstone as C
import unicorn as U

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.strings
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.color.enhance as E
import pwndbg.color.memory as M
import pwndbg.dbg
import pwndbg.enhance
import pwndbg.integration
import pwndbg.lib.memory
import pwndbg.lib.regs
from pwndbg import color
from pwndbg.color.syntax_highlight import syntax_highlight

if pwndbg.dbg.is_gdblib_available():
    import gdb


def parse_consts(u_consts) -> Dict[str, int]:
    """
    Unicorn "consts" is a python module consisting of a variable definition
    for each known entity. We repack it here as a dict for performance.

    Maps "UC_*" -> integer value of the constant
    """
    consts: Dict[str, int] = {}
    for name in dir(u_consts):
        if name.startswith("UC_"):
            consts[name] = getattr(u_consts, name)
    return consts


# Generate Map<Register name, unicorn constant>
def create_reg_to_const_map(
    base_consts: Dict[str, int], additional_mapping: Dict[str, int] = None
) -> Dict[str, int]:
    # base_consts is Map<"UC_*_REG_", constant>
    # additional mapping is the manually additions that add to the returned dict

    # Create a map of "register_name" -> Capstone ID, for faster lookup
    # Example of one field in the mapping for x86: { "RAX": 35 }
    reg_to_const: Dict[str, int] = {}

    r = re.compile(r"^UC_.*_REG_(.*)$")
    for k, v in base_consts.items():
        # Use regex to match the Capstone register names to our register names.
        # Ex: extract "RCX" from "UC_X86_REG_RCX"
        # All are uppercase
        m = r.match(k)

        if m:
            reg_to_const[m.group(1)] = v

    if additional_mapping is not None:
        reg_to_const.update(additional_mapping)

    return reg_to_const


# Map our internal architecture names onto Unicorn Engine's architecture types.
arch_to_UC = {
    "i386": U.UC_ARCH_X86,
    "x86-64": U.UC_ARCH_X86,
    "mips": U.UC_ARCH_MIPS,
    "sparc": U.UC_ARCH_SPARC,
    "arm": U.UC_ARCH_ARM,
    "armcm": U.UC_ARCH_ARM,
    "aarch64": U.UC_ARCH_ARM64,
    # 'powerpc': U.UC_ARCH_PPC,
    "rv32": U.UC_ARCH_RISCV,
    "rv64": U.UC_ARCH_RISCV,
    "s390x": U.UC_ARCH_S390X,
}

# Architecture specific maps: Map<"UC_*_REG_*",constant>
arch_to_UC_consts = {
    "i386": parse_consts(U.x86_const),
    "x86-64": parse_consts(U.x86_const),
    "mips": parse_consts(U.mips_const),
    "sparc": parse_consts(U.sparc_const),
    "arm": parse_consts(U.arm_const),
    "armcm": parse_consts(U.arm_const),
    "aarch64": parse_consts(U.arm64_const),
    "rv32": parse_consts(U.riscv_const),
    "rv64": parse_consts(U.riscv_const),
    "s390x": parse_consts(U.s390x_const),
}

# Architecture specific maps: Map<reg_name, Unicorn constant>
arch_to_reg_const_map = {
    "i386": create_reg_to_const_map(arch_to_UC_consts["i386"]),
    "x86-64": create_reg_to_const_map(
        arch_to_UC_consts["x86-64"],
        {"FSBASE": U.x86_const.UC_X86_REG_FS_BASE, "GSBASE": U.x86_const.UC_X86_REG_GS_BASE},
    ),
    "mips": create_reg_to_const_map(arch_to_UC_consts["mips"]),
    "sparc": create_reg_to_const_map(arch_to_UC_consts["sparc"]),
    "arm": create_reg_to_const_map(arch_to_UC_consts["arm"]),
    "armcm": create_reg_to_const_map(arch_to_UC_consts["armcm"]),
    "aarch64": create_reg_to_const_map(
        arch_to_UC_consts["aarch64"], {"CPSR": U.arm64_const.UC_ARM64_REG_NZCV}
    ),
    "rv32": create_reg_to_const_map(arch_to_UC_consts["rv32"]),
    "rv64": create_reg_to_const_map(arch_to_UC_consts["rv64"]),
    "s390x": create_reg_to_const_map(arch_to_UC_consts["s390x"]),
}

# Architectures for which we want to enable virtual TLB mode
enable_virtual_tlb = {
    "s390x": True,
}

# combine the flags with | operator. -1 for all
(
    NO_DEBUG,
    DEBUG_INIT,
    DEBUG_EXECUTING,
    DEBUG_MEM_MAP,
    DEBUG_HOOK_CHANGE,
    DEBUG_MEM_READ,
    DEBUG_EMU_START_STOP,
    DEBUG_INTERRUPT,
    DEBUG_TRACE,
) = (0, 1, 2, 4, 8, 16, 32, 64, 128)

DEBUG = NO_DEBUG
# DEBUG = -1 # ALL
# DEBUG = DEBUG_EXECUTING | DEBUG_MEM_MAP | DEBUG_MEM_READ

if DEBUG != NO_DEBUG:

    def debug(debug_type, fmt, args=()) -> None:
        if DEBUG & debug_type:
            print(fmt % args)

else:

    def debug(debug_type, fmt, args=()) -> None:
        pass


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
    U.UC_ARCH_ARM64: [C.aarch64_const.AARCH64_INS_SVC],
    U.UC_ARCH_PPC: [C.ppc_const.PPC_INS_SC],
    U.UC_ARCH_RISCV: [C.riscv_const.RISCV_INS_ECALL],
}

ARM_BANNED_INSTRUCTIONS = {
    C.arm.ARM_INS_MRC,
    C.arm.ARM_INS_MRRC,
    C.arm.ARM_INS_MRC2,
    C.arm.ARM_INS_MRRC2,
}
# We stop emulation when hitting these instructions, since they depend on co-processors or other information
# unavailable to the emulator
BANNED_INSTRUCTIONS = {
    "mips": {C.mips.MIPS_INS_RDHWR},
    "arm": ARM_BANNED_INSTRUCTIONS,
    "armcm": ARM_BANNED_INSTRUCTIONS,
    "aarch64": {C.aarch64.AARCH64_INS_MRS},
}

# https://github.com/unicorn-engine/unicorn/issues/550
blacklisted_regs = ["ip", "cs", "ds", "es", "fs", "gs", "ss"]

"""
e = pwndbg.emu.emulator.Emulator()
e.until_jump()
"""


class InstructionExecutedResult(NamedTuple):
    address: int
    size: int


# Instantiating an instance of `Emulator` will start an instance
# with a copy of the current processor state.
class Emulator:
    def __init__(self) -> None:
        self.arch = pwndbg.aglib.arch.name

        if self.arch not in arch_to_UC:
            raise NotImplementedError(f"Cannot emulate code for {self.arch}")

        # Mapping of Pwndbg register name to Unicorn constant for the register
        self.const_regs = arch_to_reg_const_map[self.arch]

        self.uc_mode = self.get_uc_mode()
        debug(DEBUG_INIT, "# Instantiating Unicorn for %s", self.arch)
        debug(DEBUG_INIT, "uc = U.Uc(%r, %r)", (arch_to_UC[self.arch], self.uc_mode))
        self.uc = U.Uc(arch_to_UC[self.arch], self.uc_mode)

        if enable_virtual_tlb.get(self.arch, False):
            debug(DEBUG_INIT, "# Setting TLB mode to virtual")
            self.uc.ctl_set_tlb_mode(U.UC_TLB_VIRTUAL)  # type: ignore[attr-defined]

        self.regs: pwndbg.lib.regs.RegisterSet = pwndbg.aglib.regs.current

        # Whether the emulator is allowed to emulate instructions
        # There are cases when the emulator is incorrect or we want to disable it for certain instruction types,
        # and so we can set this to False to indicate that we should not allow the emulator to continue to step
        self.valid = True

        # Jump tracking state
        self._prev = None
        self._prev_size = None
        self._curr = None

        # The address of the last successfully executed instruction using single_step
        self.last_pc = None

        # (address_successfully_executed, size_of_instruction)
        self.last_single_step_result = InstructionExecutedResult(None, None)

        # Initialize the register state
        for emu_reg in self.regs.emulated_regs_order:
            reg = emu_reg.name
            enum = self.get_reg_enum(reg)

            if not reg:
                debug(DEBUG_INIT, "# Could not set register %r", reg)
                continue

            if reg in blacklisted_regs:
                debug(DEBUG_INIT, "Skipping blacklisted register %r", reg)
                continue
            value = getattr(pwndbg.aglib.regs, reg)
            if None in (enum, value):
                if reg not in blacklisted_regs:
                    debug(DEBUG_INIT, "# Could not set register %r", reg)
                continue

            # Most registers are initialized to zero.
            # However, some registers (CPSR on AArch64) do not default to zero, so we must explicitly set them to 0
            if not emu_reg.force_write and value == 0:
                continue

            name = f"U.x86_const.UC_X86_REG_{reg.upper()}"
            debug(DEBUG_INIT, "uc.reg_write(%(name)s, %(value)#x)", locals())
            self.uc.reg_write(enum, value)

        # Add a hook for unmapped memory
        self.hook_add(U.UC_HOOK_MEM_UNMAPPED, self.hook_mem_invalid)

        # Always stop executing as soon as there's an interrupt.
        self.hook_add(U.UC_HOOK_INTR, self.hook_intr)

        # Map in the page that $pc is on
        self.map_page(pwndbg.aglib.regs.pc)

        # Instruction tracing
        if DEBUG & DEBUG_TRACE:
            self.hook_add(U.UC_HOOK_CODE, self.trace_hook)

    @property
    def last_step_succeeded(self) -> bool:
        return None not in self.last_single_step_result

    def read_register(self, name: str):
        reg = self.get_reg_enum(name)

        if reg:
            return self.uc.reg_read(reg)

        return None
        # raise AttributeError(f"AttributeError: {self!r} object has no register {name!r}")

    # Read size worth of memory, return None on error
    def read_memory(self, address: int, size: int) -> bytes | None:
        # Don't attempt if the address is not mapped on the host process
        if not pwndbg.aglib.vmmap.find(address):
            return None

        value = None
        try:
            # Raises UcError if failed
            # If the memory is not mapped, it will fail. It will not attempt to run the UC_HOOK_MEM_UNMAPPED hook
            # https://github.com/unicorn-engine/unicorn/blob/d4b92485b1a228fb003e1218e42f6c778c655809/uc.c#L569
            value = self.uc.mem_read(address, size)
        except U.unicorn.UcError as e:
            # Attempt to map the page manually and try again
            if e.errno == U.UC_ERR_READ_UNMAPPED:
                try:
                    first_page = pwndbg.lib.memory.page_align(address)
                    last_page_exclusive = pwndbg.lib.memory.page_align(
                        address + size + pwndbg.lib.memory.PAGE_SIZE
                    )

                    for page_addr in range(
                        first_page, last_page_exclusive, pwndbg.lib.memory.PAGE_SIZE
                    ):
                        if not (self.map_page(page_addr)):
                            return None

                    # Pages are mapped, try again
                    value = self.uc.mem_read(address, size)

                except U.unicorn.UcError:
                    debug(DEBUG_MEM_READ, "Emulator failed to read memory at %#x, %r", (address, e))

                    return None
            else:
                return None

        return bytes(value)

    # Recursively dereference memory, return list of addresses
    # read_size typically must be either 1, 2, 4, or 8. It dictates the size to read
    # Naturally, if it is less than the pointer size, then only one value would be telescoped
    def telescope(self, address: int, limit: int, read_size: int = None) -> List[int]:
        read_size = read_size if read_size is not None else pwndbg.aglib.arch.ptrsize

        result = [address]

        # This prevents a crash in `unpack_size` below with big (SIMD) memory reads
        if not read_size <= 8:
            return result

        for i in range(limit):
            if result.count(address) >= 2:
                break

            value = self.read_memory(address, read_size)
            if value is not None:
                # address = pwndbg.aglib.arch.unpack(value)
                address = pwndbg.aglib.arch.unpack_size(value, read_size)
                address &= pwndbg.aglib.arch.ptrmask
                result.append(address)
            else:
                break

        return result

    # Given an address, return a string like the one `pwndbg.chain.format` returns,
    # reading from the emulator memory
    def format_telescope(self, address: int, limit: int) -> str:
        address_list = self.telescope(address, limit)
        return self.format_telescope_list(address_list, limit)

    def format_telescope_list(
        self, chain: List[int], limit: int, enhance_string_len: int = None
    ) -> str:
        # Code is near identical to pwndbg.chain.format, but takes into account reading from
        # the emulator's memory when necessary
        arrow_left = pwndbg.chain.c.arrow(f" {pwndbg.chain.config_arrow_left} ")
        arrow_right = pwndbg.chain.c.arrow(f" {pwndbg.chain.config_arrow_right} ")

        # Colorize the chain
        rest = []
        for link in chain:
            symbol = pwndbg.aglib.symbol.resolve_addr(link) or None
            if symbol:
                symbol = f"{link:#x} ({symbol})"
            rest.append(M.get(link, symbol))

        # If the dereference limit is zero, skip any enhancements.
        if limit == 0:
            return rest[0]

        # Otherwise replace last element with the enhanced information.
        rest = rest[:-1]

        # Enhance the last entry
        # If there are no pointers (e.g. eax = 0x41414141), then enhance it
        if len(chain) == 1:
            enhanced = self.telescope_enhance(
                chain[-1], code=True, enhance_string_len=enhance_string_len
            )
        elif len(chain) < limit + 1:
            enhanced = self.telescope_enhance(
                chain[-2], code=True, enhance_string_len=enhance_string_len
            )
        else:
            enhanced = pwndbg.chain.c.contiguous_marker(f"{pwndbg.chain.config_contiguous}")

        if len(chain) == 1:
            return enhanced

        return arrow_right.join(rest) + arrow_left + enhanced

    def telescope_enhance(self, value: int, code: bool = True, enhance_string_len: int = None):
        # Near identical to pwndbg.enhance.enhance, just read from emulator memory

        # Determine if its on a page - we do this in the real processes memory
        page = pwndbg.aglib.vmmap.find(value)
        can_read = True
        if not page or None is pwndbg.aglib.memory.peek(value):
            can_read = False

        if not can_read:
            return E.integer(pwndbg.enhance.int_str(value))

        instr = None
        exe = page and page.execute
        rwx = page and page.rwx

        # For the purpose of following pointers, don't display
        # anything on the stack or heap as 'code'
        if "[stack" in page.objfile or "[heap" in page.objfile:
            rwx = exe = False

        # If integration doesn't think it's in a function, don't display it as code.
        if not pwndbg.integration.provider.is_in_function(value):
            rwx = exe = False

        if exe:
            pwndbg_instr = pwndbg.aglib.disasm.disassembly.one_raw(value)
            if pwndbg_instr:
                instr = f"{pwndbg_instr.mnemonic} {pwndbg_instr.op_str}"
                if pwndbg.config.syntax_highlight:
                    instr = syntax_highlight(instr)

        # szval = pwndbg.aglib.strings.get(value) or None
        # Read from emulator memory
        szval = self.memory_read_string(value, max_string_len=enhance_string_len, max_read=None)
        szval0 = szval
        if szval:
            szval = E.string(repr(szval))

        # Fix for case when we can't read the end address anyway (#946)
        if value + pwndbg.aglib.arch.ptrsize > page.end:
            return E.integer(pwndbg.enhance.int_str(value))

        # Read from emulator memory
        # intval = int(pwndbg.aglib.memory.get_typed_pointer_value(pwndbg.aglib.typeinfo.pvoid, value))
        read_value = self.read_memory(value, pwndbg.aglib.arch.ptrsize)
        if read_value is not None:
            # intval = pwndbg.aglib.arch.unpack(read_value)
            intval = pwndbg.aglib.arch.unpack_size(read_value, pwndbg.aglib.arch.ptrsize)
        else:
            # This occurs when Unicorn fails to read the memory - which it shouldn't, as the
            # read_memory call will map the pages necessary, and this function assumes
            # that the pointer is a valid pointer (as it has already been telescoped)
            intval = 0

        intval0 = intval
        if 0 <= intval < 10:
            intval = E.integer(str(intval))
        else:
            intval = E.integer("%#x" % int(intval & pwndbg.aglib.arch.ptrmask))

        retval = []

        if not code:
            instr = None

        # If it's on the stack, don't display it as code in a chain.
        if instr and "[stack" in page.objfile:
            retval = [intval, szval]
        # If it's RWX but a small value, don't display it as code in a chain.
        elif instr and rwx and intval0 < 0x1000:
            retval = [intval, szval]
        # If it's an instruction and *not* RWX, display it unconditionally
        elif instr and exe:
            if not rwx:
                if szval:
                    retval = [instr, szval]
                else:
                    retval = [instr]
            else:
                retval = [instr, intval, szval]

        # Otherwise strings have preference
        elif szval:
            if len(szval0) < pwndbg.aglib.arch.ptrsize:
                retval = [intval, szval]
            else:
                retval = [szval]

        # And then integer
        else:
            return E.integer(pwndbg.enhance.int_str(intval0))

        retval_final: Tuple[str] = tuple(filter(lambda x: x is not None, retval))

        if len(retval_final) == 0:
            return E.unknown("???")

        if len(retval_final) == 1:
            return retval_final[0]

        return retval_final[0] + E.comment(color.strip(f" /* {'; '.join(retval_final[1:])} */"))

    # Return None if cannot find str
    def memory_read_string(self, address: int, max_string_len=None, max_read=None) -> str | None:
        if max_string_len is None:
            max_string_len = pwndbg.aglib.strings.length

        if max_read is None:
            max_read = pwndbg.aglib.strings.length

        # Read string
        sz = self.read_memory(address, max_read)
        if sz is None:
            return None

        try:
            sz = sz[: sz.index(b"\x00")]
        except ValueError:
            return None

        sz = sz.decode("latin-1", "replace")

        if not sz or not all(s in string.printable for s in sz):
            return None

        if len(sz) < max_string_len or not max_string_len:
            return sz

        return sz[:max_string_len] + "..."

    def __getattr__(self, name: str):
        reg = self.get_reg_enum(name)

        if reg:
            return self.uc.reg_read(reg)

        raise AttributeError(f"AttributeError: {self!r} object has no attribute {name!r}")

    def update_pc(self, pc=None) -> None:
        if pc is None:
            pc = pwndbg.aglib.regs.pc
        self.uc.reg_write(self.get_reg_enum(self.regs.pc), pc)

    def read_thumb_bit(self) -> int:
        """
        Return 0 or 1, representing the status of the Thumb bit in the current Arm architecture

        This reads from the emulator itself, meaning this can be read to determine a state
        transitions between non-Thumb and Thumb mode

        Return None if the Thumb bit is not relevent to the current architecture

        Mimics the `read_thumb_bit` function defined in aglib/arch.py
        """
        if self.arch == "arm":
            if (cpsr := self.cpsr) is not None:
                return (cpsr >> 5) & 1
        elif self.arch == "armcm":
            if (xpsr := self.xpsr) is not None:
                return (xpsr >> 24) & 1
        return 0

    def get_uc_mode(self):
        """
        Retrieve the mode used by Unicorn for the current architecture.
        """
        arch = pwndbg.aglib.arch.name
        mode = 0

        if arch == "armcm":
            mode |= (
                (U.UC_MODE_MCLASS | U.UC_MODE_THUMB)
                if (pwndbg.aglib.regs.xpsr & (1 << 24))
                else U.UC_MODE_MCLASS
            )

        elif arch in ("arm", "aarch64"):
            mode |= U.UC_MODE_THUMB if (pwndbg.aglib.regs.cpsr & (1 << 5)) else U.UC_MODE_ARM

        elif (
            arch == "mips"
            and pwndbg.dbg.is_gdblib_available()
            and "isa32r6" in gdb.newest_frame().architecture().name()
        ):
            mode |= U.UC_MODE_MIPS32R6
        elif arch == "s390x":
            pass  # fails with invalid mode error otherwise
        else:
            mode |= {4: U.UC_MODE_32, 8: U.UC_MODE_64}[pwndbg.aglib.arch.ptrsize]

        if pwndbg.aglib.arch.endian == "little":
            mode |= U.UC_MODE_LITTLE_ENDIAN
        else:
            mode |= U.UC_MODE_BIG_ENDIAN

        return mode

    def map_page(self, page) -> bool:
        page = pwndbg.lib.memory.page_align(page)
        size = pwndbg.lib.memory.PAGE_SIZE

        debug(DEBUG_MEM_MAP, "# Mapping %#x-%#x", (page, page + size))

        try:
            data = pwndbg.aglib.memory.read(page, size)
            data = bytes(data)
        except pwndbg.dbg_mod.Error:
            debug(DEBUG_MEM_MAP, "Could not map page %#x during emulation! [exception]", page)
            return False

        if not data:
            debug(DEBUG_MEM_MAP, "Could not map page %#x during emulation! [no data]", page)
            return False

        debug(DEBUG_MEM_MAP, "uc.mem_map(%(page)#x, %(size)#x)", locals())
        self.uc.mem_map(page, size)

        debug(DEBUG_MEM_MAP, "# Writing %#x bytes", len(data))
        debug(DEBUG_MEM_MAP, "uc.mem_write(%(page)#x, ...)", locals())
        self.uc.mem_write(page, data)

        return True

    def hook_mem_invalid(self, uc, access, address, size: int, value, user_data) -> bool:
        debug(DEBUG_MEM_MAP, "# Invalid access at %#x, attempting to map the page", address)

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

    def hook_intr(self, uc, intno, user_data) -> None:
        """
        We never want to emulate through an interrupt.  Just stop.
        """
        debug(DEBUG_INTERRUPT, "Got an interrupt - %d", intno)
        self.valid = False
        self.uc.emu_stop()

    def get_reg_enum(self, reg: str) -> int | None:
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
        # if reg in self.regs.all:
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
        debug(DEBUG_HOOK_CHANGE, "%r = uc.hook_add(*%r, **%r)", (rv, a, kw))
        return rv

    def hook_del(self, *a, **kw):
        debug(DEBUG_HOOK_CHANGE, "uc.hook_del(*%r, **%r)", (a, kw))
        return self.uc.hook_del(*a, **kw)

    # Can throw a UcError(status)
    def emu_start(self, *a, **kw):
        debug(DEBUG_EMU_START_STOP, "uc.emu_start(*%r, **%r)", (a, kw))
        return self.uc.emu_start(*a, **kw)

    def emu_stop(self, *a, **kw):
        debug(DEBUG_EMU_START_STOP, "uc.emu_stop(*%r, **%r)", (a, kw))
        return self.uc.emu_stop(*a, **kw)

    def emulate_with_hook(self, hook, count=512) -> None:
        ident = self.hook_add(U.UC_HOOK_CODE, hook)

        pc: int = self.pc
        # Unicorn appears to disregard the UC_MODE_THUMB mode passed into the constructor, and instead
        # determines Thumb mode based on the PC that is passed to the `emu_start` function
        # https://github.com/unicorn-engine/unicorn/issues/391
        #
        # Because we single-step the emulator, we always have to read the Thumb bit from the emulator
        # and set the least significant bit of the PC to 1 if the bit is 1 in order to enable Thumb mode
        # for the execution of the next instruction. If this `emulate_with_hook` executes multiple instructions
        # which have Thumb mode transitions, Unicorn will internally handle them.
        pc |= self.read_thumb_bit()

        try:
            self.emu_start(pc, 0, count=count)
        finally:
            self.hook_del(ident)

    def mem_read(self, *a, **kw):
        debug(DEBUG_MEM_READ, "uc.mem_read(*%r, **%r)", (a, kw))
        return self.uc.mem_read(*a, **kw)

    def until_jump(self, pc: int = None):
        """
        Emulates instructions starting at the specified address until the
        program counter is set to an address which does not linearly follow
        the previously-emulated instruction.

        Arguments:
            pc: Address to start at.  If `None`, uses the current instruction.

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

        # Add the jump hook, start emulating, and remove the hook.
        self.emulate_with_hook(self.until_jump_hook_code)

        # We're done emulating
        return self._prev, self._curr

    def until_jump_hook_code(self, _uc, address, instruction_size: int, _user_data) -> None:
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
            debug(DEBUG_EXECUTING, "%#x %#X --> %#x", (self._prev, self._prev_size, self._curr))
            self.emu_stop()
            return

        self._prev = address
        self._prev_size = instruction_size

    def until_call(self, pc=None):
        addr, target = self.until_jump(pc)

        while target and not pwndbg.aglib.disasm.disassembly.one_raw(addr).call_like:
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

    def until_syscall_hook_code(self, uc, address, size: int, user_data) -> None:
        data = binascii.hexlify(self.mem_read(address, size))
        debug(
            DEBUG_EXECUTING, "# Executing instruction at %(address)#x with bytes %(data)s", locals()
        )
        self.until_syscall_address = address

    def single_step(self, pc=None) -> Tuple[int, int]:
        """Steps one instruction.

        Yields:
            Each iteration, yields a tuple of (address_just_executed, instruction_size).

            Returns (None, None) upon failure to execute the instruction
        """

        # If the emulator has been manually marked as invalid, we should no longer step it
        if not self.valid:
            return InstructionExecutedResult(None, None)

        self.last_single_step_result = InstructionExecutedResult(None, None)

        pc = pc or self.pc

        insn = pwndbg.aglib.disasm.disassembly.one_raw(pc)

        # If we don't know how to disassemble, bail.
        if insn is None:
            debug(DEBUG_EXECUTING, "Can't disassemble instruction at %#x", pc)
            return self.last_single_step_result

        if insn.id in BANNED_INSTRUCTIONS.get(self.arch, {}):
            debug(DEBUG_EXECUTING, "Hit illegal instruction at %#x", pc)
            return self.last_single_step_result

        debug(
            DEBUG_EXECUTING,
            "# Emulator attempting to single-step at %#x: %s %s",
            (pc, insn.mnemonic, insn.op_str),
        )

        try:
            self.single_step_hook_hit_count = 0
            self.emulate_with_hook(self.single_step_hook_code, count=1)
            if not self.valid:
                return InstructionExecutedResult(None, None)

            # If above call does not throw an Exception, we successfully executed the instruction
            self.last_pc = pc
            debug(DEBUG_EXECUTING, "Unicorn now at pc=%#x", self.pc)
        except U.unicorn.UcError:
            debug(DEBUG_EXECUTING, "Emulator failed to execute instruction")
            self.last_single_step_result = InstructionExecutedResult(None, None)

        return self.last_single_step_result

    def single_step_iter(self, pc=None):
        a = self.single_step(pc)

        while a:
            yield a
            a = self.single_step(pc)

    # Whenever Unicorn is "about to execute" an instruction, this hook is called
    # https://github.com/unicorn-engine/unicorn/issues/1434
    def single_step_hook_code(self, _uc, address: int, instruction_size: int, _user_data) -> None:
        # For whatever reason, the hook will hit twice on
        # unicorn >= 1.0.2rc4, but not on unicorn-1.0.2rc1~unicorn-1.0.2rc3,
        # So we use a counter to ensure the code run only once
        if self.single_step_hook_hit_count == 0:
            debug(DEBUG_EXECUTING, "# single_step: %#-8x", address)
            self.last_single_step_result = InstructionExecutedResult(address, instruction_size)
            self.single_step_hook_hit_count += 1

    # For debugging
    def dumpregs(self) -> None:
        for reg in (
            list(self.regs.retaddr)
            + list(self.regs.misc)
            + list(self.regs.common)
            + list(self.regs.flags)
        ):
            enum = self.get_reg_enum(reg)

            if not reg or enum is None:
                print("# Could not dump register %r" % (reg,))
                continue

            name = f"U.x86_const.UC_X86_REG_{reg.upper()}"
            value = self.uc.reg_read(enum)
            print("uc.reg_read(%s) ==> %x" % (name, value))

    def trace_hook(self, _uc, address, instruction_size: int, _user_data) -> None:
        data = binascii.hexlify(self.mem_read(address, instruction_size))
        debug(DEBUG_TRACE, "# trace_hook: %#-8x %r", (address, data))

    def __repr__(self) -> str:
        return f"Valid: {self.valid}, PC: {self.pc:#x}"
