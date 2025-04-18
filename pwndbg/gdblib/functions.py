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
        self.__doc__ = func.__doc__.strip()

        assert func.__doc__ and "The function must have a docstring."
        _first_line = self.__doc__.split("\n")[0]
        assert len(_first_line) <= 80 and (
            "The first line of the function's docstring should be short,"
            " as it is printed with `help function`."
        )
        assert _first_line[-1] == "." and (
            "The first line should be a standalone sentence, as it is "
            "printed alone with `help function`."
        )
        assert (
            "Example:\n" in func.__doc__
            and "Convenience functions need to provide a usage example."
        )

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


@GdbFunction()
def hex2ptr(hex_string: gdb.Value | str) -> int:
    """
    Converts a hex string to a little-endian address and returns the address.

    Example:
    ```
    pwndbg> p/x $hex2ptr("20 74 ed f7 ff 7f")
    $1 = 0x7ffff7ed7420
    pwndbg> p/x $hex2ptr("2074edf7ff7f")
    $2 = 0x7ffff7ed7420
    pwndbg> distance '$base("libc")' '$hex2ptr("20 74 ed f7 ff 7f")'
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
    Get the number of program arguments.
    Evaluates to argc.

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
def argv(index: gdb.Value) -> gdb.Value:
    """
    Get the n-th program argument.
    Evaluate argv on the supplied value.

    Example:
    ```
    pwndbg> p $argv(0)
    $11 = (signed char *) 0x7fffffffe666 "/usr/bin/sh"
    pwndbg> argv
    00:0000│  0x7fffffffe2a8 —▸ 0x7fffffffe666 ◂— '/usr/bin/sh'
    01:0008│  0x7fffffffe2b0 ◂— 0
    ```
    """
    val = pwndbg.aglib.argv.argv(int(index))
    if val is None:
        raise gdb.GdbError("Arg not found")
    return dbg_value_to_gdb(val)


@GdbFunction(only_when_running=True)
def environ(env_name: gdb.Value) -> gdb.Value:
    """
    Get an environment variable by name.
    Evaluate getenv() on the supplied value.

    Example:
    ```
    pwndbg> p $environ("LANG")
    $2 = (signed char *) 0x7fffffffebfb "LANG=en_US.UTF-8"
    ```
    """
    name = env_name.string()
    if not name:
        raise gdb.GdbError("No environment variable name provided")

    val = pwndbg.aglib.argv.environ(name)
    if val is None:
        raise gdb.GdbError("Environ not found")
    return dbg_value_to_gdb(val)


@GdbFunction(only_when_running=True)
def envp(index: gdb.Value) -> gdb.Value:
    """
    Get the n-th environment variable.
    Evaluate envp on the supplied value.

    Example:
    ```
    pwndbg> p $envp(0x3F)
    $13 = (signed char *) 0x7fffffffef7d "LANG=en_US.UTF-8"
    pwndbg> p $envp(0x3F) == $environ("LANG")
    $14 = 1
    ```
    """
    val = pwndbg.aglib.argv.envp(int(index))
    if val is None:
        raise gdb.GdbError("Environ not found")
    return dbg_value_to_gdb(val)


def dbg_value_to_gdb(d: pwndbg.dbg_mod.Value) -> gdb.Value:
    from pwndbg.dbg.gdb import GDBValue

    assert isinstance(d, GDBValue)
    return d.inner


@GdbFunction(only_when_running=True)
def fsbase(offset: gdb.Value = gdb.Value(0)) -> int:
    """
    Get the value of the FS segment register.
    Only valid on x86(-64).

    Example:
    ```
    pwndbg> p/x $fsbase()
    $3 = 0x7ffff7cdab80
    pwndbg> p $fs_base == $fsbase()
    $4 = 1
    pwndbg> x/gx $fsbase(0x28)
    0x7ffff7cdaba8:	0x4da926e1668e5a00
    pwndbg> x/gx $fsbase(0x30)
    0x7ffff7cdabb0:	0x190a86d93bccf0ad
    pwndbg> tls
    Thread Local Storage (TLS) base: 0x7ffff7cdab80
    TLS is located at:
        0x7ffff7cda000     0x7ffff7cdc000 rw-p     2000      0 [anon_7ffff7cda]
    Dumping the address:
    tcbhead_t @ 0x7ffff7cdab80
        0x00007ffff7cdab80 +0x0000 tcb                  : 0x7ffff7cdab80
        0x00007ffff7cdab88 +0x0008 dtv                  : 0x7ffff7cdb4f0
        0x00007ffff7cdab90 +0x0010 self                 : 0x7ffff7cdab80
        0x00007ffff7cdab98 +0x0018 multiple_threads     : 0x0
        0x00007ffff7cdab9c +0x001c gscope_flag          : 0x0
        0x00007ffff7cdaba0 +0x0020 sysinfo              : 0x0
        0x00007ffff7cdaba8 +0x0028 stack_guard          : 0x4da926e1668e5a00
        0x00007ffff7cdabb0 +0x0030 pointer_guard        : 0x190a86d93bccf0ad
        [...]
    pwndbg> canary
    [...]
    Canary    = 0x4da926e1668e5a00 (may be incorrect on != glibc)
    [...]
    ```
    FS will usually point to the start of the TLS. If you're not providing an
    offset, it is usually easier to use gdb's builtin $fs_base variable.
    """
    if pwndbg.aglib.arch.name not in ("i386", "x86-64"):
        raise gdb.GdbError("This function is only valid on i386 and x86-64.")

    return pwndbg.aglib.regs.fsbase + int(offset)


@GdbFunction(only_when_running=True)
def gsbase(offset: gdb.Value = gdb.Value(0)) -> int:
    """
    Get the value of the GS segment register.
    Only valid on x86(-64).

    Example:
    ```
    pwndbg> p/x $gsbase()
    $1 = 0x0
    ```
    The value of the GS register is more interesting when doing kernel debugging:
    ```
    pwndbg> p/x $gsbase()
    $1 = 0xffff999287a00000
    pwndbg> tele $gsbase()
    00:0000│  0xffff999287a00000 ◂— 0
    ... ↓     4 skipped
    05:0028│  0xffff999287a00028 ◂— 0xd6aa9b336d52a400
    06:0030│  0xffff999287a00030 ◂— 0
    07:0038│  0xffff999287a00038 ◂— 0
    pwndbg> p $gsbase() == $gs_base
    $2 = 1
    ```
    If you're not providing an offset, it is usually easier to use gdb's
    builtin $gs_base variable.
    """
    if pwndbg.aglib.arch.name not in ("i386", "x86-64"):
        raise gdb.GdbError("This function is only valid on i386 and x86-64.")
    return pwndbg.aglib.regs.gsbase + int(offset)
