from random import choice

TIPS = [
    "GDB and Pwndbg parameters can be shown or set with `show <param>` and `set <param> <value>` GDB commands",
    "GDB's `apropos <topic>` command displays all registered commands that are related to the given <topic>",
    "GDB's `follow-fork-mode` parameter can be used to set whether to trace parent or child after fork() calls",
    "Use Pwndbg's `config` and `theme` commands to tune its configuration and theme colors!",
    "Pwndbg mirrors some of Windbg commands like eq, ew, ed, eb, es, dq, dw, dd, db, ds for writing and reading memory",
    "Pwndbg resolves kernel memory maps by parsing page tables (default) or via `monitor info mem` QEMU gdbstub command (use `set kernel-vmmap-via-page-tables off` for that)",
    "Use the `context` (`ctx` for short) command to display the context once again. You can reconfigure the context layout with `set context-section <sections>` or forward the output to a file/tty via `set context-output <file>`. See also `config context` to configure it further!",
    "Use the `canary` command to see all stack canary/cookie values on the stack (based on the *usual* stack canary value initialized by glibc)",
    "Use the `procinfo` command for better process introspection (than the GDB's `info proc` command)",
]


def get_tip_of_the_day() -> str:
    return choice(TIPS)
