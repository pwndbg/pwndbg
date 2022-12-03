"""
Allows describing functions, specifically enumerating arguments which
may be passed in a combination of registers and stack values.
"""
import gdb
from capstone import CS_GRP_CALL
from capstone import CS_GRP_INT

import pwndbg.chain
import pwndbg.constants
import pwndbg.disasm
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.ida
import pwndbg.lib.abi
import pwndbg.lib.funcparser
import pwndbg.lib.functions
from pwndbg.commands.nearpc import c as N

ida_replacements = {
    "__int64": "signed long long int",
    "__int32": "signed int",
    "__int16": "signed short",
    "__int8": "signed char",
    "__uint64": "unsigned long long int",
    "__uint32": "unsigned int",
    "__uint16": "unsigned short",
    "__uint8": "unsigned char",
    "_BOOL_1": "unsigned char",
    "_BOOL_2": "unsigned short",
    "_BOOL_4": "unsigned int",
    "_BYTE": "unsigned char",
    "_WORD": "unsigned short",
    "_DWORD": "unsigned int",
    "_QWORD": "unsigned long long",
    "__pure": "",
    "__hidden": "",
    "__return_ptr": "",
    "__struct_ptr": "",
    "__array_ptr": "",
    "__fastcall": "",
    "__cdecl": "",
    "__thiscall": "",
    "__userpurge": "",
}


def get_syscall_name(instruction):
    if CS_GRP_INT not in instruction.groups:
        return None

    syscall_register = pwndbg.lib.abi.ABI.syscall().syscall_register
    syscall_arch = pwndbg.gdblib.arch.current

    # On x86/x64 `syscall` and `int <value>` instructions are in CS_GRP_INT
    # but only `syscall` and `int 0x80` actually execute syscalls on Linux.
    # So here, we return no syscall name for other instructions and we also
    # handle a case when 32-bit syscalls are executed on x64
    if syscall_register in ("eax", "rax"):
        mnemonic = instruction.mnemonic

        is_32bit = mnemonic == "int" and instruction.op_str == "0x80"
        if not (mnemonic == "syscall" or is_32bit):
            return None

        # On x64 the int 0x80 instruction executes 32-bit syscalls from i386
        # On x86, the syscall_arch is already i386, so its all fine
        if is_32bit:
            syscall_arch = "i386"

    syscall_number = getattr(pwndbg.gdblib.regs, syscall_register)
    return pwndbg.constants.syscall(syscall_number, syscall_arch) or "<unk_%d>" % syscall_number


def get(instruction):
    """
    Returns an array containing the arguments to the current function,
    if $pc is a 'call' or 'bl' type instruction.

    Otherwise, returns None.
    """
    n_args_default = 4

    if instruction is None:
        return []

    if instruction.address != pwndbg.gdblib.regs.pc:
        return []

    if CS_GRP_CALL in instruction.groups:
        try:
            abi = pwndbg.lib.abi.ABI.default()
        except KeyError:
            return []

        # Not sure of any OS which allows multiple operands on
        # a call instruction.
        assert len(instruction.operands) == 1

        target = instruction.operands[0].int

        if not target:
            return []

        name = pwndbg.gdblib.symbol.get(target)
        if not name:
            return []
    elif CS_GRP_INT in instruction.groups:
        # Get the syscall number and name
        name = get_syscall_name(instruction)
        abi = pwndbg.lib.abi.ABI.syscall()
        target = None

        if name is None:
            return []
    else:
        return []

    result = []
    name = name or ""

    sym = gdb.lookup_symbol(name)
    name = name.replace("isoc99_", "")  # __isoc99_sscanf
    name = name.replace("@plt", "")  # getpwiod@plt

    # If we have particular `XXX_chk` function in our database, we use it.
    # Otherwise, we show args for its unchecked version.
    # We also lstrip `_` in here, as e.g. `__printf_chk` needs the underscores.
    if name not in pwndbg.lib.functions.functions:
        name = name.replace("_chk", "")
        name = name.strip().lstrip("_")  # _malloc

    func = pwndbg.lib.functions.functions.get(name, None)

    # Try to extract the data from GDB.
    # Note that this is currently broken, pending acceptance of
    # my patch: https://sourceware.org/ml/gdb-patches/2015-06/msg00268.html
    if sym and sym[0]:
        try:
            n_args_default = len(sym[0].type.fields())
        except TypeError:
            pass

    # Try to grab the data out of IDA
    if not func and target:
        typename = pwndbg.ida.GetType(target)

        if typename:
            typename += ";"

            # GetType() does not include the name.
            typename = typename.replace("(", " function_name(", 1)

            for k, v in ida_replacements.items():
                typename = typename.replace(k, v)

            func = pwndbg.lib.funcparser.ExtractFuncDeclFromSource(typename + ";")

    if func:
        args = func.args
    else:
        args = (
            pwndbg.lib.functions.Argument("int", 0, argname(i, abi)) for i in range(n_args_default)
        )

    for i, arg in enumerate(args):
        result.append((arg, argument(i, abi)))

    return result


def argname(n, abi=None):
    abi = abi or pwndbg.lib.abi.ABI.default()
    regs = abi.register_arguments

    if n < len(regs):
        return regs[n]

    return "arg[%i]" % n


def argument(n, abi=None):
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    Works only for ABIs that use registers for arguments.
    """
    abi = abi or pwndbg.lib.abi.ABI.default()
    regs = abi.register_arguments

    if n < len(regs):
        return getattr(pwndbg.gdblib.regs, regs[n])

    n -= len(regs)

    sp = pwndbg.gdblib.regs.sp + (n * pwndbg.gdblib.arch.ptrsize)

    return int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.ppvoid, sp))


def arguments(abi=None):
    """
    Yields (arg_name, arg_value) tuples for arguments from a given ABI.
    Works only for ABIs that use registers for arguments.
    """
    abi = abi or pwndbg.lib.abi.ABI.default()
    regs = abi.register_arguments

    for i in range(len(regs)):
        yield argname(i, abi), argument(i, abi)


def format_args(instruction):
    result = []
    for arg, value in get(instruction):
        code = arg.type != "char"
        pretty = pwndbg.chain.format(value, code=code)

        # Enhance args display
        if arg.name == "fd" and isinstance(value, int):
            path = pwndbg.gdblib.file.readlink("/proc/%d/fd/%d" % (pwndbg.gdblib.proc.pid, value))
            if path:
                pretty += " (%s)" % path

        result.append("%-10s %s" % (N.argument(arg.name) + ":", pretty))
    return result
