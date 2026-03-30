# Bare-metal debugging

When debugging an embedded device, or any other process with [MMIO](https://en.wikipedia.org/wiki/Memory-mapped_I/O_and_port-mapped_I/O) peripherals for that matter, the debugger should not read nor write certain regions of memory as doing so may cause unwanted side-effects (including changing the CPU state and registers).

In most cases, it is impossible for the debugger to detect which regions of memory are safe to read/write, and which ones aren't, and it should thus avoid touching *any* memory unless explicitly allowed to by the user.

To prevent Pwndbg from wreaking havoc in the address space, you may set these options in your `.gdbinit` when doing debugging on such targets:
```
set remotetimeout 20
set auto-explore-pages no
set auto-explore-auxv no
set auto-explore-stack no
# disable the stack
set context-sections regs disasm code backtrace expressions threads heap_tracker
set dereference-limit 0
```
The `.gdbinit` file can be in your project-specific folder, and will be loaded after your `~/.gdbinit`.

