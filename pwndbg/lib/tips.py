from __future__ import annotations

import re
from random import choice
from typing import List

from pwndbg.color import message

TIPS: List[str] = [
    # GDB hints
    "GDB's `apropos <topic>` command displays all registered commands that are related to the given <topic>",
    "GDB's `follow-fork-mode` parameter can be used to set whether to trace parent or child after fork() calls",
    'Use GDB\'s `dprintf` command to print all calls to given function. E.g. `dprintf malloc, "malloc(%p)\\n", (void*)$rdi` will print all malloc calls',
    "Use GDB's `pi` command to run an interactive Python console where you can use Pwndbg APIs like `pwndbg.gdblib.memory.read(addr, len)`, `pwndbg.gdblib.memory.write(addr, data)`, `pwndbg.gdb.vmmap.get()` and so on!",
    "GDB's `set directories <path>` parameter can be used to debug e.g. glibc sources like the malloc/free functions!",
    "If you have debugging symbols the `info args` command shows current frame's function arguments (use `up` and `down` to switch between frames)",
    'Calling functions like `call (void)puts("hello world")` will run all other target threads for the time the function runs. Use `set scheduler-locking on` to lock the execution to current thread when calling functions',
    # Pwndbg hints
    "If you want Pwndbg to clear screen on each command (but still save previous output in history) use `set context-clear-screen on`",
    "The `set show-flags on` setting will display CPU flags register in the regs context panel",
    "GDB and Pwndbg parameters can be shown or set with `show <param>` and `set <param> <value>` GDB commands",
    "Use Pwndbg's `config` and `theme` commands to tune its configuration and theme colors!",
    "Pwndbg mirrors some of Windbg commands like `eq`, `ew`, `ed`, `eb`, `es`, `dq`, `dw`, `dd`, `db`, `ds` for writing and reading memory",
    "Pwndbg resolves kernel memory maps by parsing page tables (default) or via `monitor info mem` QEMU gdbstub command (use `set kernel-vmmap-via-page-tables off` for that)",
    "Use the `vmmap` command for a better & colored memory maps display (than the GDB's `info proc mappings`)",
    "Use the `telescope` command to dereference a given address/pointer multiple times (if the dereferenced value is a valid ptr; see `config telescope` to configure its behavior)",
    "Use the `context` (or `ctx`) command to display the context once again. You can reconfigure the context layout with `set context-section <sections>` or forward the output to a file/tty via `set context-output <file>`. See also `config context` to configure it further!",
    "Disable Pwndbg context information display with `set context-sections ''`",
    "Pwndbg context displays where the program branches to thanks to emulating few instructions into the future. You can disable this with `set emulate off` which may also speed up debugging",
    "Use the `canary` command to see all stack canary/cookie values on the stack (based on the *usual* stack canary value initialized by glibc)",
    "Use the `procinfo` command for better process introspection (than the GDB's `info proc` command)",
    "Want to display each context panel in a separate tmux window? See https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md#splitting--layouting-context",
    'Use `$base("heap")` to get the start address of a [heap] memory page',
    "Use the `errno` (or `errno <number>`) command to see the name of the last or provided (libc) error",
    "Pwndbg sets the SIGLARM, SIGBUS, SIGPIPE and SIGSEGV signals so they are not passed to the app; see `info signals` for full GDB signals configuration",
    "Use `vmmap -A|-B <number> <filter>` to display <number> of maps after/before filtered ones",
    "Use the `killall` command to kill all specified threads (via their ids)",
    "Use the `spray` command to spray memory with cyclic pattern or specified value",
    "Use `patch <address> '<assembly>'` to patch an address with given assembly code",
    "Want to NOP some instructions? Use `patch <address> 'nop; nop; nop'`",
    "`heap_config` shows heap related configuration",
    "`break-if-taken` and `break-if-not-taken` commands sets breakpoints after a given jump instruction was taken or not",
    "`stepuntilasm <assembly-instruction [operands]>` steps program forward until matching instruction occures",
    "Use `plist` command to dump elements of linked list",
    "If your program has multiple threads they will be displayed in the context display or using the `context threads` command",
    "Use `track-got enable|info|query` to track GOT accesses - useful for hijacking control flow via writable GOT/PLT",
    "Need to `mmap` or `mprotect` memory in the debugee? Use commands with the same name to inject and run such syscalls",
    "Use `hi` to see if a an address belongs to a glibc heap chunk",
]


def get_tip_of_the_day() -> str:
    return choice(TIPS)


def color_tip(tip: str) -> str:
    return re.sub("`(.*?)`", lambda s: message.warn(s.group()[1:-1]), tip)
