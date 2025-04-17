from __future__ import annotations

from typing import Tuple

import gdb

import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.gdblib.functions
import pwndbg.integration.binja
from pwndbg.color import message


@pwndbg.gdblib.functions.GdbFunction()
@pwndbg.integration.binja.with_bn()
def bn_sym(name_val: gdb.Value) -> int | None:
    """
    Lookup a symbol's address by name from Binary Ninja.

    Example:
    ```
    pwndbg> set integration-provider binja
    Pwndbg successfully connected to Binary Ninja (4.2.6455 Personal) xmlrpc: http://127.0.0.1:31337
    Set which provider to use for integration features to 'binja'.
    pwndbg> p main
    No symbol "main" in current context.
    pwndbg> p/x $bn_sym("main")
    $2 = 0x555555555645
    pwndbg> b *($bn_sym("main"))
    Breakpoint 1 at 0x555555555645
    ```
    """
    name = name_val.string()
    addr: int | None = pwndbg.integration.binja._bn.get_symbol_addr(name)
    if addr is None:
        return None
    return pwndbg.integration.binja.r2l(addr)


@pwndbg.gdblib.functions.GdbFunction()
@pwndbg.integration.binja.with_bn()
def bn_var(name_val: gdb.Value) -> int | None:
    """
    Lookup a stack variable's address by name from Binary Ninja.

    Example:
    ```
    pwndbg> set integration-provider binja
    Pwndbg successfully connected to Binary Ninja (4.2.6455 Personal) xmlrpc: http://127.0.0.1:31337
    Set which provider to use for integration features to 'binja'.
    pwndbg> p var_10
    No symbol "var_10" in current context.
    pwndbg> p/x $bn_var("var_10")
    $4 = 0x7fffffffe118
    pwndbg> vmmap $4
        0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    ►   0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack] +0x20118
    ```

    It seems this function doesn't work on renamed variables.
    """
    name = name_val.string()
    conf_and_offset: Tuple[int, int] | None = pwndbg.integration.binja._bn.get_var_offset_from_sp(
        pwndbg.integration.binja.l2r(pwndbg.aglib.regs.pc), name
    )
    if conf_and_offset is None:
        return None
    (conf, offset) = conf_and_offset
    if conf < 64:
        print(message.warn(f"Warning: Stack offset only has {conf / 255 * 100:.2f}% confidence"))
    return pwndbg.aglib.regs.sp + offset


@pwndbg.gdblib.functions.GdbFunction()
@pwndbg.integration.binja.with_bn()
def bn_eval(expr: gdb.Value) -> int | None:
    """
    Parse and evaluate a Binary Ninja expression.

    Read more about binary ninja expressions here:
    https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView.parse_expression

    All registers in the current register set are available as magic variables (e.g. $rip).
    The $piebase magic variable is also included, with the computed executable base.

    Example:
    ```
    pwndbg> set integration-provider binja
    Pwndbg successfully connected to Binary Ninja (4.2.6455 Personal) xmlrpc: http://127.0.0.1:31337
    Set which provider to use for integration features to 'binja'.
    pwndbg> p $bn_expr("0x20+0x10")
    Invalid data type for function to be called.
    ```

    This function doesn't seem to work.
    """
    magic_vars = {}
    for r in pwndbg.aglib.regs.current:
        v = pwndbg.aglib.regs[r]
        if v is not None:
            magic_vars[r] = v
    magic_vars["piebase"] = pwndbg.aglib.proc.binary_base_addr
    ret: int | None = pwndbg.integration.binja._bn.parse_expr(expr.string(), magic_vars)
    return ret
