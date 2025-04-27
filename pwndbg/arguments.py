"""
Allows describing functions, specifically enumerating arguments which
may be passed in a combination of registers and stack values.
"""

from __future__ import annotations

from typing import List
from typing import Tuple

from capstone import CS_GRP_INT

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.arch
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.chain
import pwndbg.integration
import pwndbg.lib.abi
import pwndbg.lib.funcparser
import pwndbg.lib.functions
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.aglib.nearpc import c as N


def get(instruction: PwndbgInstruction) -> List[Tuple[pwndbg.lib.functions.Argument, int]]:
    """
    Returns an array containing the arguments to the current function,
    if $pc is a 'call', 'bl', or 'jalr' type instruction.

    Otherwise, returns None.
    """
    n_args_default = 4

    if instruction is None:
        return []

    if instruction.address != pwndbg.aglib.regs.pc:
        return []

    if instruction.call_like:
        abi = pwndbg.aglib.arch.function_abi

        if abi is None:
            return []

        target = instruction.target

        if not target:
            return []

        name = pwndbg.aglib.symbol.resolve_addr(target)
        if not name:
            return []
    elif CS_GRP_INT in instruction.groups:
        # Get the syscall number and name
        name = instruction.syscall_name
        abi = pwndbg.aglib.arch.syscall_abi
        target = None

        if name is None or abi is None:
            return []
    else:
        return []

    result = []
    name = name or ""

    sym = pwndbg.aglib.symbol.lookup_frame_symbol(name)
    name = name.replace("isoc99_", "")  # __isoc99_sscanf
    name = name.replace("@plt", "")  # getpwiod@plt

    # If we have particular `XXX_chk` function in our database, we use it.
    # Otherwise, we show args for its unchecked version.
    # We also lstrip `_` in here, as e.g. `__printf_chk` needs the underscores.
    if name not in pwndbg.lib.functions.functions:
        name = name.replace("_chk", "")
        name = name.strip().lstrip("_")  # _malloc

    func = pwndbg.lib.functions.functions.get(name, None)

    if sym:
        try:
            target_type = sym.type.target()
        except Exception:
            target_type = sym.type

        if target_type and target_type.code == pwndbg.dbg_mod.TypeCode.FUNC:
            func_args = target_type.func_arguments()
            if func_args is not None:
                n_args_default = len(func_args)

    # Try to grab the data out of IDA
    if not func and target:
        func = pwndbg.integration.provider.get_func_type(target)

    if func:
        args = func.args
    else:
        args = (
            pwndbg.lib.functions.Argument("int", 0, argname(i, abi)) for i in range(n_args_default)
        )

    for i, arg in enumerate(args):
        result.append((arg, argument(i, abi)))

    return result


def argname(n: int, abi: pwndbg.lib.abi.ABI) -> str:
    regs = abi.register_arguments

    if n < len(regs):
        return regs[n]

    return "arg[%i]" % n


def argument(n: int, abi: pwndbg.lib.abi.ABI | None = None) -> int:
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    Works only for ABIs that use registers for arguments.
    """
    abi = abi or pwndbg.aglib.arch.function_abi
    if abi is None:
        raise pwndbg.dbg_mod.Error(
            f"Function ABI not defined for current architecture, {pwndbg.aglib.arch.function_abi}"
        )
    regs = abi.register_arguments

    if n < len(regs):
        return getattr(pwndbg.aglib.regs, regs[n])

    n -= len(regs)

    sp = pwndbg.aglib.regs.sp + (n * pwndbg.aglib.arch.ptrsize)

    return int(pwndbg.aglib.memory.get_typed_pointer_value(pwndbg.aglib.typeinfo.ppvoid, sp))


def arguments(abi: pwndbg.lib.abi.ABI | None = None):
    """
    Yields (arg_name, arg_value) tuples for arguments from a given ABI.
    Works only for ABIs that use registers for arguments.
    """
    abi = abi or pwndbg.aglib.arch.function_abi
    if abi is None:
        return []
    regs = abi.register_arguments

    for i in range(len(regs)):
        yield argname(i, abi), argument(i, abi)


def format_args(instruction: PwndbgInstruction) -> List[str]:
    result = []
    for arg, value in get(instruction):
        code = arg.type != "char"
        pretty = pwndbg.chain.format(value, code=code)

        # Enhance args display
        if arg.name == "fd" and isinstance(value, int):
            # Cannot find PID of the QEMU program: perhaps it is in a different pid namespace or we have no permission to read the QEMU process' /proc/$pid/fd/$fd file.
            pid = pwndbg.aglib.proc.pid
            if pid is not None:
                path = pwndbg.aglib.file.readlink("/proc/%d/fd/%d" % (pid, value))
                if path:
                    pretty += f" ({path})"

        result.append("%-10s %s" % (N.argument(arg.name) + ":", pretty))
    return result
