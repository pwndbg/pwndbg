import argparse

import gdb
import pwnlib
from pwnlib import asm

import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.gdblib.file
import pwndbg.lib.which
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.lib.regs import reg_sets

parser = argparse.ArgumentParser(
    description="""
Calls the mprotect syscall and prints its result value

Note that the mprotect syscall may fail for various reasons
(see `man mprotect`) and a non-zero error return value
can be decoded with the `errno <value>` command.

Examples:
    mprotect $rsp PROT_READ|PROT_WRITE|PROT_EXEC
    mprotect some_symbol PROT_NONE
"""
)
parser.add_argument(
    "addr", help="Page-aligned address to all mprotect on.", type=pwndbg.commands.sloppy_gdb_parse
)
parser.add_argument(
    "length",
    help="Count of bytes to call mprotect on. Needs " "to be multiple of page size.",
    type=int,
)
parser.add_argument(
    "prot", help="Prot string as in mprotect(2). Eg. " '"PROT_READ|PROT_EXEC"', type=str
)

SYS_MPROTECT = 0x7D

prot_dict = {
    "PROT_NONE": 0x0,
    "PROT_READ": 0x1,
    "PROT_WRITE": 0x2,
    "PROT_EXEC": 0x4,
}


def prot_str_to_val(protstr):
    """Heuristic to convert PROT_EXEC|PROT_WRITE to integer value."""
    prot_int = 0
    for k in prot_dict:
        if k in protstr:
            prot_int |= prot_dict[k]
    return prot_int


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def mprotect(addr, length, prot):

    prot_int = prot_str_to_val(prot)

    # generate a shellcode that executes the mprotect syscall
    shellcode_asm = pwnlib.shellcraft.syscall(
        "SYS_mprotect", int(pwndbg.lib.memory.page_align(addr)), int(length), int(prot_int)
    )
    shellcode = asm.asm(shellcode_asm)

    # obtain the registers that need to be saved for the current platform
    # we save the registers that are used for arguments, return value and the program counter
    current_regs = reg_sets[pwndbg.gdblib.arch.current]
    regs_to_save = current_regs.args + (current_regs.retval, current_regs.pc)

    # save the registers
    saved_registers = {reg: pwndbg.gdblib.regs[reg] for reg in regs_to_save}

    # save the memory which will be overwritten by the shellcode
    saved_instruction_bytes = pwndbg.gdblib.memory.read(
        saved_registers[current_regs.pc], len(shellcode)
    )
    pwndbg.gdblib.memory.write(saved_registers[current_regs.pc], shellcode)

    # execute syscall
    gdb.execute("nextsyscall")
    gdb.execute("stepi")

    # get the return value
    ret = pwndbg.gdblib.regs[current_regs.retval]

    print("mprotect returned %d (%s)" % (ret, current_regs.retval))

    # restore registers and memory
    pwndbg.gdblib.memory.write(saved_registers[current_regs.pc], saved_instruction_bytes)

    # restore the registers
    for register, value in saved_registers.items():
        setattr(pwndbg.gdblib.regs, register, value)
