from __future__ import annotations

import argparse
import struct

from pwnlib import shellcraft

import pwndbg.aglib
import pwndbg.aglib.asm
import pwndbg.aglib.shellcode
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.lib.regs
from pwndbg.commands import CommandCategory
from pwndbg.commands.hijack_fd import exec_shellcode_with_stack
from pwndbg.commands.hijack_fd import stack_size_alignment

RLIM_INFINITY = -1
LIMITS: dict[str, int] = {
    "core": 4,
    "cpu": 0,
    "fsize": 1,
    "data": 2,
    "stack": 3,
    "nofile": 7,
    "as": 9,
}

parser = argparse.ArgumentParser(
    description="Set a POSIX resource limit in the debugged process.",
)
parser.add_argument(
    "resource",
    type=str.lower,
    choices=sorted(LIMITS.keys()),
    help="Which resource to limit",
)
parser.add_argument(
    "soft",
    type=str,
    help="Soft limit value (integer) or 'infinite'",
)
parser.add_argument(
    "hard",
    type=str,
    nargs="?",
    default=None,
    help="Hard limit value (integer) or 'infinite' (defaults to soft)",
)


def to_int_limit(val: str) -> int:
    lv = val.lower()
    if lv in ("infinite", "unlimited"):
        return RLIM_INFINITY
    try:
        return int(val)
    except ValueError:
        print(message.error(f"Invalid limit '{val}'"))
        raise


def asm_setrlimit(num: int, soft_val: int, hard_val: int) -> tuple[int, bytes]:
    ptrsize = pwndbg.aglib.arch.ptrsize

    if ptrsize == 8:
        rlimit_data = struct.pack(
            "<QQ",
            soft_val & 0xFFFFFFFFFFFFFFFF,
            hard_val & 0xFFFFFFFFFFFFFFFF,
        )
    else:
        rlimit_data = struct.pack(
            "<II",
            soft_val & 0xFFFFFFFF,
            hard_val & 0xFFFFFFFF,
        )

    stack_size = stack_size_alignment(len(rlimit_data))

    register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.name]
    stack_reg = register_set.stack

    asm = "".join(
        [
            shellcraft.pushstr(rlimit_data, False),
            shellcraft.setrlimit(num, stack_reg),
        ]
    )

    return stack_size, pwndbg.aglib.asm.asm(asm)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def setrlimit(resource: str, soft: str, hard: str | None = None) -> None:
    """
    Sets a POSIX resource limit in the debugged process via the setrlimit syscall.
    Usage: setrlimit <resource> <soft> [hard]
    """

    res = resource.lower()

    try:
        soft_val = to_int_limit(soft)
        hard_val = to_int_limit(hard) if hard is not None else soft_val
    except ValueError:
        return

    num = LIMITS[res]

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController) -> None:
        soft_str = "inf" if soft_val == RLIM_INFINITY else str(soft_val)
        hard_str = "inf" if hard_val == RLIM_INFINITY else str(hard_val)
        print(
            f"calling setrlimit for resource {res!r} (resource={num}): "
            f"soft={soft_str}, hard={hard_str}"
        )

        stack_size, asm_bin = asm_setrlimit(num, soft_val, hard_val)

        async with exec_shellcode_with_stack(ec, asm_bin, stack_size):
            register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.name]
            ret = pwndbg.aglib.regs.read_reg(register_set.retval)
            print(
                message.success(f"Set {res} limit (return={ret}): soft={soft_str}, hard={hard_str}")
            )

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)
