from random import choice

TIPS = [
    # GDB hints
    "GDB's `apropos <topic>` command displays all registered commands that are related to the given <topic>",
    "GDB's `follow-fork-mode` parameter can be used to set whether to trace parent or child after fork() calls",
    'Use GDB\'s `dprintf` command to print all calls to given function. E.g. `dprintf malloc, "malloc(%p)\\n", (void*)$rdi` will print all malloc calls',
    "Use GDB\'s `pi` command to run an interactive Python console where you can use Pwndbg APIs like `pwndbg.memory.read(addr, len)`, `pwndbg.memory.write(addr, data)`, `pwndbg.vmmap.get()` and so on!",
    "GDB's `set directories <path>` parameter can be used to debug e.g. glibc sources like the malloc/free functions!",

    # Pwndbg hints
    "GDB and Pwndbg parameters can be shown or set with `show <param>` and `set <param> <value>` GDB commands",
    "Use Pwndbg's `config` and `theme` commands to tune its configuration and theme colors!",
    "Pwndbg mirrors some of Windbg commands like `eq`, `ew`, `ed`, `eb`, `es`, `dq`, `dw`, `dd`, `db`, `ds` for writing and reading memory",
    "Pwndbg resolves kernel memory maps by parsing page tables (default) or via `monitor info mem` QEMU gdbstub command (use `set kernel-vmmap-via-page-tables off` for that)",
    "Use the `vmmap` instruction for a better & colored memory maps display (than the GDB's `info proc mappings`)",
    "Use the `telescope` command to dereference a given address/pointer multiple times (if the dereferenced value is a valid ptr; see `config telescope` to configure its behavior)",
    "Use the `context` (or `ctx`) command to display the context once again. You can reconfigure the context layout with `set context-section <sections>` or forward the output to a file/tty via `set context-output <file>`. See also `config context` to configure it further!",
    "Disable Pwndbg context information display with `set context-sections ''`",
    "Pwndbg context displays where the program branches to thanks to emulating few instructions into the future. You can disable this with `set emulate off` which may also speed up debugging",
    "Use the `canary` command to see all stack canary/cookie values on the stack (based on the *usual* stack canary value initialized by glibc)",
    "Use the `procinfo` command for better process introspection (than the GDB's `info proc` command)",
    "Want to display each context panel in a separate tmux window? See https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md#splitting--layouting-context",
]


def get_tip_of_the_day() -> str:
    return choice(TIPS)
