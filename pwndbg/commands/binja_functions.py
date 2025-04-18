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

    This function sees symbols like functions and global variables,
    but not stack local variables, use `bn_var` for that.

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

    This function doesn't see functions or global variables,
    use `bn_sym` for that.

    Example:
    ```
    pwndbg> set integration-provider binja
    Pwndbg successfully connected to Binary Ninja (4.2.6455 Personal) xmlrpc: http://127.0.0.1:31337
    Set which provider to use for integration features to 'binja'.
    pwndbg> p user_choice
    No symbol "user_choice" in current context.
    pwndbg> p/x $bn_var("user_choice")
    $4 = 0x7fffffffe118
    pwndbg> vmmap $4
        0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    ►   0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack] +0x20118
    pwndbg> p/x $bn_var("main")
    TypeError: Could not convert Python object: None.
    Error while executing Python code.
    ```
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

    This function cannot see stack local variables.

    Example:
    ```
    pwndbg> set integration-provider binja
    Pwndbg successfully connected to Binary Ninja (4.2.6455 Personal) xmlrpc: http://127.0.0.1:31337
    Set which provider to use for integration features to 'binja'.
    pwndbg> p/x $bn_eval("10+20")
    $6 = 0x30
    pwndbg> p/x $bn_eval("main")
    $7 = 0x1645
    pwndbg> p/x $rebase($bn_eval("main"))
    $8 = 0x555555555645
    pwndbg> p some_global_var
    No symbol "some_global_var" in current context.
    pwndbg> p/x $rebase($bn_eval("some_global_var+$rax"))
    $9 = 0x5555555586b8
    pwndbg> p $rebase($bn_eval("some_global_var+$rax")) == $bn_sym("some_global_var") + $rax
    $10 = 1
    pwndbg> p $bn_eval("$piebase+some_global_var+$rax") == $bn_sym("some_global_var") + $rax
    $11 = 1
    ```
    """
    magic_vars = {}
    for r in pwndbg.aglib.regs.current:
        v = pwndbg.aglib.regs[r]
        if v is not None:
            magic_vars[r] = v
    magic_vars["piebase"] = pwndbg.aglib.proc.binary_base_addr
    ret: int | None = pwndbg.integration.binja._bn.parse_expr(expr.string(), magic_vars)
    return ret
