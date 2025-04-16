"""
Put all functions defined for gdb in here.

This file might be changed into a module in the future.
"""

from __future__ import annotations

import functools
from typing import Any
from typing import Callable
from typing import List

import gdb

import pwndbg.aglib.argv
import pwndbg.aglib.elf
import pwndbg.aglib.proc
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
from pwndbg.lib.common import hex2ptr_common

functions: List[_GdbFunction] = []


def GdbFunction(only_when_running: bool = False) -> Callable[..., Any]:
    return functools.partial(_GdbFunction, only_when_running=only_when_running)


class _GdbFunction(gdb.Function):
    def __init__(self, func: Callable[..., Any], only_when_running: bool) -> None:
        self.name = func.__name__
        self.func = func
        self.only_when_running = only_when_running
        self.__doc__ = func.__doc__

        assert("Example:" in func.__doc__ and "Convenience functions need to provide a usage example.")

        functions.append(self)

        super().__init__(self.name)

        functools.update_wrapper(self, func)

    def invoke(self, *args: gdb.Value) -> Any:
        if self.only_when_running and not pwndbg.aglib.proc.alive:
            # Returning empty string is a workaround that we can't stop e.g. `break *$rebase(offset)`
            # Thx to that, gdb will print out 'evaluation of this expression requires the target program to be active'
            return ""

        return self.func(*args)

    def __call__(self, *args: gdb.Value) -> Any:
        return self.invoke(*args)


@GdbFunction(only_when_running=True)
def rebase(addr: gdb.Value | int) -> int:
    """
    Return address rebased onto the executable's mappings.

    Example:
    ```
    pwndbg> p/x $rebase(0xd9020)
    $1 = 0x55555562d020
    pwndbg> vmmap
    0x555555554000     0x55555556f000 r--p    1b000      0 /usr/bin/bash
    0x55555556f000     0x55555562d000 r-xp    be000  1b000 /usr/bin/bash
    0x55555562d000     0x55555565e000 r--p    31000  d9000 /usr/bin/bash
    [...]
    pwndbg> p $rebase(0xd9020) == 0x555555554000 + 0xd9020
    $2 = 1
    pwndbg> tele $rebase(0xd9020)
    00:0000│  0x55555562d020 ◂— 0x204900636f6c6c61 /* 'alloc' */
    01:0008│  0x55555562d028 ◂— 'have no name!'
    02:0010│  0x55555562d030 ◂— 0x65720021656d616e /* 'name!' */
    03:0018│  0x55555562d038 ◂— 'adline stdin'
    [...]
    ```
    """
    base = pwndbg.aglib.elf.exe().address
    return base + int(addr)


@GdbFunction(only_when_running=True)
def base(name_pattern: gdb.Value | str) -> int:
    """
    Return the base address of the first memory mapping containing the given name.

    Example:
    ```
    pwndbg> p/x $base("libc")
    $4 = 0x7ffff7d4b000
    pwndbg> vmmap libc
        0x7ffff7d4a000     0x7ffff7d4b000 rw-p     1000  6e000 /usr/lib/libncursesw.so.6.5
    ►   0x7ffff7d4b000     0x7ffff7d6f000 r--p    24000      0 /usr/lib/libc.so.6
    ►   0x7ffff7d6f000     0x7ffff7ed6000 r-xp   167000  24000 /usr/lib/libc.so.6
    ►   0x7ffff7ed6000     0x7ffff7f2b000 r--p    55000 18b000 /usr/lib/libc.so.6
    ►   0x7ffff7f2b000     0x7ffff7f2f000 r--p     4000 1e0000 /usr/lib/libc.so.6
    ►   0x7ffff7f2f000     0x7ffff7f31000 rw-p     2000 1e4000 /usr/lib/libc.so.6
        0x7ffff7f31000     0x7ffff7f39000 rw-p     8000      0 [anon_7ffff7f31]
    pwndbg> tele $base(\\"libc\\")+0x1337
    00:0000│  0x7ffff7d4c337 ◂— 0x80480a04214000f0
    01:0008│  0x7ffff7d4c33f ◂— 0x8040c02204452040
    02:0010│  0x7ffff7d4c347 ◂— 0x20042400000200
    03:0018│  0x7ffff7d4c34f ◂— 0x20 /* ' ' */
    [...]
    ```

    Beware of accidentally matching the wrong mapping. For instance, if the loaded
    executable contained the string "libc" anywhere in it's path, it would've been
    returned.
    """
    if isinstance(name_pattern, gdb.Value):
        name = name_pattern.string()
    else:
        name = name_pattern

    for p in pwndbg.aglib.vmmap.get():
        if name in p.objfile:
            return p.vaddr
    raise ValueError(f"No mapping named {name}")


@GdbFunction(only_when_running=True)
def hex2ptr(hex_string: gdb.Value | str) -> int:
    """
    Converts a hex string to a little-endian address and returns the address.

    Example:
    ```
    pwndbg> dist $base(\\"libc\\") '$hex2ptr("20 74 ed f7 ff 7f")'
    0x7ffff7d4b000->0x7ffff7ed7420 is 0x18c420 bytes (0x31884 words)
    ```

    Especially useful for quickly converting pwntools output.
    """
    if isinstance(hex_string, gdb.Value):
        hex_string = hex_string.string()

    hex_string = hex_string.replace(" ", "")
    pointer = hex2ptr_common(hex_string)
    return pointer


@GdbFunction(only_when_running=True)
def argc() -> int:
    """
    Evaluates to argc. Get the number of program arguments.

    Example:
    ```
    pwndbg> p $argc()
    $1 = 2
    pwndbg> argv
    00:0000│  0x7fffffffe288 —▸ 0x7fffffffe659 ◂— '/usr/bin/cat'
    01:0008│  0x7fffffffe290 —▸ 0x7fffffffe666 ◂— 'gdbinit.py'
    02:0010│  0x7fffffffe298 ◂— 0
    ```
    """
    return pwndbg.aglib.argv.argc()


@GdbFunction(only_when_running=True)
def argv(number_value: gdb.Value) -> gdb.Value:
    """
    Evaluate argv on the supplied value. Get the
    n-th program argument.

    Example:
    ```
    pwndbg> p $argv(0)
    $11 = (signed char *) 0x7fffffffe666 "/usr/bin/sh"
    pwndbg> argv
    00:0000│  0x7fffffffe2a8 —▸ 0x7fffffffe666 ◂— '/usr/bin/sh'
    01:0008│  0x7fffffffe2b0 ◂— 0
    ```
    """
    val = pwndbg.aglib.argv.argv(int(number_value))
    if val is None:
        raise gdb.GdbError("Arg not found")
    return dbg_value_to_gdb(val)


@GdbFunction(only_when_running=True)
def envp(number_value: gdb.Value) -> gdb.Value:
    """
    Evaluate envp on the supplied value. Get the
    n-th environment variable.

    Example:
    ```
    pwndbg> p $envp(0x3F)
    $13 = (signed char *) 0x7fffffffef7d "LANG=en_US.UTF-8"
    pwndbg> p $envp(0x3F) == $environ("LANG")
    $14 = 1
    ```
    """
    val = pwndbg.aglib.argv.envp(int(number_value))
    if val is None:
        raise gdb.GdbError("Environ not found")
    return dbg_value_to_gdb(val)


@GdbFunction(only_when_running=True)
def environ(name_value: gdb.Value) -> gdb.Value:
    """
    Evaluate getenv() on the supplied value. Get an
    environment variable by name.

    Example:
    ```
    pwndbg> p $environ("LANG")
    $2 = (signed char *) 0x7fffffffebfb "LANG=en_US.UTF-8"
    ```
    """
    name = name_value.string()
    if not name:
        raise gdb.GdbError("No environment variable name provided")

    val = pwndbg.aglib.argv.environ(name)
    if val is None:
        raise gdb.GdbError("Environ not found")
    return dbg_value_to_gdb(val)


def dbg_value_to_gdb(d: pwndbg.dbg_mod.Value) -> gdb.Value:
    from pwndbg.dbg.gdb import GDBValue

    assert isinstance(d, GDBValue)
    return d.inner
