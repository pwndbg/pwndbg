"""
Function and syscall argument formatting.

Enumerates arguments which may be passed in a combination of
registers and stack values.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any

from capstone6pwndbg import CS_GRP_INT

import pwndbg.aglib
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.objc
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.chain
import pwndbg.dbg_mod
import pwndbg.enhance
import pwndbg.lib.abi
import pwndbg.lib.functions
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.aglib.nearpc import c as N
from pwndbg.lib.arch import Platform
from pwndbg.lib.functions import Argument
from pwndbg.lib.functions import Function
from pwndbg.lib.functions import format_flags_argument

syscall_data: Any = None


def get_all_syscall_data() -> None:
    global syscall_data
    data_path = resources.files("pwndbg.lib") / "syscall_data" / "data.json"
    with data_path.open() as file:
        syscall_data = json.load(file)


def parse_arg(arg: str) -> tuple[str, int, str]:
    """
    Returns [type name, deref count, name].
    """

    _IDENT_RE = re.compile(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$")

    arg = arg.strip()

    m = _IDENT_RE.search(arg)
    assert m

    name = m.group(1)
    assert isinstance(name, str)

    type_part = arg[: m.start()].strip()
    deref = type_part.count("*")

    type_str = type_part.replace("*", " ")
    type_str = " ".join(type_str.split())

    return (type_str, deref, name)


def make_syscall_func_impl(name: str, abi: pwndbg.lib.abi.SyscallABI) -> Function | None:
    abi_lookup = {
        pwndbg.lib.abi.linux_i386_syscall: "x86",
        pwndbg.lib.abi.linux_amd64_syscall: "x64",
        pwndbg.lib.abi.linux_arm_syscall: "arm",
        pwndbg.lib.abi.linux_aarch64_syscall: "arm64",
        pwndbg.lib.abi.linux_mips_syscall: "mipso32",
        pwndbg.lib.abi.linux_mips64_syscall: "mips64",
        pwndbg.lib.abi.linux_ppc_syscall: "ppc",
        pwndbg.lib.abi.linux_ppc64_syscall: "ppc64",
        pwndbg.lib.abi.linux_riscv32_syscall: None,
        pwndbg.lib.abi.linux_riscv64_syscall: "riscv64",
    }
    abi_name = abi_lookup.get(abi)
    if abi_name is None:
        return None
    call_data = [call for call in syscall_data["syscalls"][abi_name] if call["name"] == name]
    args = []
    if len(call_data) == 0:
        return None
    call_data = call_data[0]
    nargs = call_data["nargs"]
    for i in range(nargs):
        t, d, n = parse_arg(call_data[f"arg{i}"])
        args.append(Argument(type=t, derefcnt=d, name=n))
    return Function(type="long", derefcnt=0, name=f"SYS_{name}", args=args)


def make_syscall_func(name: str, abi: pwndbg.lib.abi.SyscallABI) -> Function | None:
    if syscall_data is None:
        get_all_syscall_data()
    return make_syscall_func_impl(name, abi)


def get(instruction: PwndbgInstruction) -> list[tuple[pwndbg.lib.functions.Argument, int]]:
    """
    Returns an array containing the arguments to the current function,
    if $pc is a function call or syscall instruction.

    Otherwise, returns None.
    """

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

        original_name = name or ""

        name = original_name.replace("isoc99_", "")  # __isoc99_sscanf
        name = name.replace("@plt", "")  # getpwiod@plt

        # If we have particular `XXX_chk` function in our database, we use it.
        # Otherwise, we show args for its unchecked version.
        # We also lstrip `_` in here, as e.g. `__printf_chk` needs the underscores.
        if name not in pwndbg.lib.functions.functions:
            name = name.replace("_chk", "")
            name = name.strip().lstrip("_")  # _malloc

        func: Function | None = None
        if pwndbg.aglib.arch.platform == Platform.DARWIN:
            # Try to resolve an Objective-C method call.
            #
            # Checking this first keeps us from resolving these as simple calls to
            # `objc_msgSend` and functions like it, which have definitions that are
            # rather barren of semantics in comparison.
            func = pwndbg.aglib.objc.try_resolve_call_at_current_pc(instruction)

        if func is None:
            # If more specific call information can't be determined, use the regular
            # function resolution flow.
            func = pwndbg.lib.functions.functions.get(name, None)

    elif CS_GRP_INT in instruction.groups:
        # Get the syscall number and name
        name = instruction.syscall_name
        abi = pwndbg.aglib.arch.syscall_abi
        target = None

        if name is None or abi is None:
            return []

        func = make_syscall_func(name, abi)

        original_name = name  # allow fallback in case func is null

    else:
        return []

    # FIXME(provider, integration): Add this feature back at some point
    # Try to grab the data out of IDA
    # if not func and target:
    #    func = pwndbg.dintegration.provider.get_func_type(target)

    if func:
        args = func.args
        if len(args) > 1 and args[-1].name == "vararg":
            format_value = pwndbg.enhance.enhance(argument(len(args) - 2, abi))
            m = re.findall(
                r"%[-+ #0]?(?:[0-9]+|\*)?(?:\.(?:[0-9]+|\*))?(?:hh|h|l|ll|q|L|j|z|Z|t)?[diuoxXfFeEgGaAcsCSpn]",
                format_value,
            )
            vararg_cnt = len(m)
            if vararg_cnt > 0:
                args.pop()
                args += [
                    pwndbg.lib.functions.Argument("int", 0, argname(len(args) + i, abi))
                    for i in range(vararg_cnt)
                ]
    else:
        n_args_default = 4
        sym = pwndbg.aglib.symbol.lookup_frame_symbol(original_name)
        if sym:
            try:
                target_type = sym.type.target()
            except Exception:
                target_type = sym.type

            if target_type and target_type.code == pwndbg.dbg_mod.TypeCode.FUNC:
                func_args = target_type.func_arguments()
                if func_args is not None:
                    n_args_default = len(func_args)
        args = (
            pwndbg.lib.functions.Argument("int", 0, argname(i, abi)) for i in range(n_args_default)
        )

    return [(arg, argument(i, abi)) for i, arg in enumerate(args)]


def argname(n: int, abi: pwndbg.lib.abi.ABI) -> str:
    regs = abi.register_arguments

    if n < len(regs):
        return regs[n]

    return f"arg[{n}]"


def argument(n: int, abi: pwndbg.lib.abi.ABI | None = None) -> int:
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    Works only for ABIs that use registers for arguments.
    """
    abi = abi or pwndbg.aglib.arch.function_abi
    if abi is None:
        raise pwndbg.dbg_mod.DebuggerError(
            f"Function ABI not defined for current architecture, {pwndbg.aglib.arch.function_abi}"
        )
    regs = abi.register_arguments

    if n < len(regs):
        return pwndbg.aglib.regs.read_reg_uncached(regs[n])

    n -= len(regs)

    sp = pwndbg.aglib.regs.sp + (n * pwndbg.aglib.arch.ptrsize)

    return pwndbg.aglib.memory.read_pointer_width(sp)


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


# When an argument is named one of these in Linux syscalls/glibc, it refers to a file descriptor
# Search for strings containing "fd" in https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
FILE_DESCRIPTOR_ARG_NAMES = {
    "fd",
    "in_fd",
    "out_fd",
    "fdin",
    "fdout",
    "oldfd",
    "fildes",
    "newfd",
    "epfd",
    "dfd",
    "dirfd",
    "mountdirfd",
}


def format_args(instruction: PwndbgInstruction) -> list[str]:
    result = []
    for arg, value in get(instruction):
        code = arg.type != "char"
        pretty = (
            pwndbg.chain.format(value, code=code)
            if not arg.flags
            else format_flags_argument(arg.flags, value)
        )

        # Enhance args display
        if arg.name in FILE_DESCRIPTOR_ARG_NAMES and isinstance(value, int):
            # Cannot find PID of the QEMU program: perhaps it is in a different pid namespace or we have no permission to read the QEMU process' /proc/$pid/fd/$fd file.
            pid = pwndbg.aglib.proc.pid()
            if pid is not None:
                path = pwndbg.aglib.file.readlink(f"/proc/{pid}/fd/{value}")
                if path:
                    pretty += f" ({path})"

        result.append(f"{N.argument(arg.name) + ':':<10} {pretty}")

    return result
