---
hide:
  - navigation
---

<!--
  This document should give an overview of some of the most interesting
  features pwndbg has to offer. Use a lot of screenshots and recordings.
  Don't go too much in-depth - it is better to write a tutorial in another
  page of the docs and simply link to it.
-->

# Features

Pwndbg has a great deal of useful features. You can a see all available commands at any time by typing the `pwndbg` command or by checking the [Commands section](commands/index.md) of the documentation. For configuration and theming see the [Configuration section](configuration/index.md). Below is a subset of commands which are easy to capture in screenshots.

## Context

A useful summary of the current execution context is printed every time GDB stops (e.g. breakpoint or single-step), displaying all registers, the stack, call frames, disassembly, and additionally recursively dereferencing all pointers.  All memory addresses are color-coded to the type of memory they represent.

![](assets/caps/context.png)

A history of previous context output is kept which can be accessed using the `contextprev` and `contextnext` commands.

### Arguments

All function call sites are annotated with the arguments to those functions.  This works best with debugging symbols, but also works in the most common case where an imported function (e.g. libc function via GOT or PLT) is used.

![](assets/caps/arguments_getenv.png)
![](assets/caps/arguments_memcpy.png)
![](assets/caps/arguments_sigsetjmp.png)
![](assets/caps/arguments_strcpy.png)
![](assets/caps/arguments_syscall.png)
![](assets/caps/arguments_xtraceinit.png)

### Splitting / Layouting Context

The context sections can be distributed among different tty by using the `contextoutput` command. Thus, if you want to make better use of some of the empty space in the default pwndbg output, you can split the panes in your terminal and redirect the various contexts among them.

![](assets/caps/context_splitting.png)

See [Splitting the Context](misc/splitting-the-context.md) for more information.

### GDB TUI
The context sections are available as native [GDB TUI](https://sourceware.org/gdb/current/onlinedocs/gdb.html/TUI.html) windows named `pwndbg_[sectionname]`. There are some predefined layouts coming with pwndbg which you can select using `layout pwndbg` or `layout pwndbg_code`.

![](assets/caps/context_tui.png)

See [GDB TUI](misc/gdb-tui.md) for more information.

### Watch Expressions

You can add expressions to be watched by the context. Those expressions are evaluated and shown on every context refresh. For instance by doing `contextwatch execute "info args"` we can see the arguments of every function we are in (here we are in `mmap`):

![](assets/caps/cwatch_infoargs.png)

See [commands/context/contextwatch.md] for more information.

### Ghidra

With the help of [radare2](https://github.com/radareorg/radare2) or [rizin](https://github.com/rizinorg/rizin) it is possible to show the
decompiled source code of the ghidra decompiler.

However, this comes with some prerequisites.
* First: you have to have installed radare2 or rizin and it must be found by gdb (within path)
* Second: you have to install the ghidra plugin for radare2
  [r2ghidra](https://github.com/radareorg/r2ghidra) or install the ghidra plugin for rizin [rz-ghidra](https://github.com/rizinorg/rz-ghidra)

* Third: r2pipe has to be installed in the python-context gdb is using (or if you are using rizin, install rzpipe instead)

The decompiled source be shown as part of the context by adding `ghidra` to `set context-sections`
or by calling `ctx-ghidra [function]` manually.

Be warned, the first call to both radare2/r2ghidra and rizin/rz-ghidra are rather slow! Subsequent requests for decompiled
source will be faster. And it does take up some resources as the radare2/rizin instance is kept by r2pipe/rzpipe
to enable faster subsequent analysis.

With those performance penalties it is reasonable to not have it launch always. Therefore it includes
an option to only start it when required with `set context-ghidra`:

* `set context-ghidra always`: always trigger the ghidra context
* `set context-ghidra never`: never trigger the ghidra context except when called manually
* `set context-ghidra if-no-source`: invoke ghidra if no source code is available

Remark: the plugin tries to guess the correct current line and mark it with "-->", but it might
get it wrong.

## Disassembly

Pwndbg uses assets/capstone Engine to display disassembled instructions, but also leverages its introspection into the instruction to extract memory targets and condition codes.

All absolute jumps are folded away, only displaying relevant instructions.

![](assets/caps/disasm_taken_folded.png)

Additionally, if the current instruction is conditional, Pwndbg displays whether or not it is evaluated with a green check or a red X, and folds away instructions as necessary.

![](assets/caps/disasm_taken_after.png)
![](assets/caps/disasm_taken_before.png)
![](assets/caps/disasn_taken_false.png)

## Emulation

Pwndbg leverages Unicorn Engine in order to only show instructions which will actually be emulated.  At each debugger stop (e.g. breakpoint or single-step) the next few instructions are silently emulated, and only instructions which will actually be executed are displayed.

This is incredibly useful when stepping through jump tables, PLT entries, and even while ROPping!

![](assets/caps/emulate_vs_disasm.png)
![](assets/caps/emulation_plt.png)
![](assets/caps/emulation_rop.png)

## Heap Inspection

Pwndbg enables introspection of the glibc allocator, ptmalloc2, via a handful of introspection functions.

![](assets/caps/heap_arena.png)
![](assets/caps/heap_mp.png)
![](assets/caps/heap_bins.png)
![](assets/caps/heap_fastbins.png)
![](assets/caps/heap_unsorted.png)
![](assets/caps/heap_smallbins.png)
![](assets/caps/heap_largebins.png)
![](assets/caps/heap_heap.png)
![](assets/caps/heap_heap2.png)
![](assets/caps/heap_mallocchunk.png)
![](assets/caps/heap_topchunk.png)
![](assets/caps/heap_fake_fast.png)
![](assets/caps/heap_try_free.png)

## IDA Pro/Binary Ninja Integration

Pwndbg is capable of integrating with IDA Pro or Binary Ninja by installing an XMLRPC server in the decompiler as a plugin, and then querying it for information.

This allows extraction of comments, decompiled lines of source, breakpoints, symbols, and synchronized debugging (single-steps update the cursor in the decompiler).

![](assets/caps/ida_comments.png)
![](assets/caps/ida_function.png)
![](assets/caps/ida_integration.png)

See the [Binary Ninja integration guide](misc/binja-integration.md) for setup information.

## Go Debugging

Pwndbg has support for dumping complex Go values like maps and slices, including automatically parsing out type layouts in certain cases.

See the [Go debugging guide](misc/go-debugging.md) for more information.

## Configuration, customization

There are two commands to set various options:

* `theme` - to set particular output color/style
![](assets/caps/theme.png)

* `config` - to set parameters like whether to emulate code near current instruction, ida rpc connection info, hexdump bytes/width (and more)
![](assets/caps/config.png)

Of course you can generate and put it in `.gdbinit` after pwndbg initialization to keep it persistent between pwngdb sessions.

This can be seen and achieved by `configfile`/`themefile` commands.

## QEMU Compatibility

Pwndbg is designed to work with minimally-implemented or otherwise debugger-hostile implementations of the GDB Serial Protocol.  One such implementation is that used by QEMU User-Mode Emulation (`qemu-user`) which is frequently used by CTF players to execute and debug cross-architecture binaries.

Vanilla GDB, PEDA, and GEF all fail terribly in this scenario.

#### GEF

![](assets/caps/qemu_gef.png)

#### PEDA

![](assets/caps/qemu_peda.png)

#### Vanilla GDB

![](assets/caps/qemu_vanilla.png)

#### Pwndbg

However, Pwndbg works around the limitations of the GDB stub to give you the best debugger environment possible.

![](assets/caps/qemu_pwndbg.png)

## Process State Inspection

Use the `procinfo` command in order to inspect the current process state, like UID, GID, Groups, SELinux context, and open file descriptors!  Pwndbg works particularly well with remote GDB debugging like with Android phones, which PEDA, GEF, and vanilla GDB choke on.

![](assets/caps/procinfo.png)

## ROP Gadgets

Pwndbg makes using ROPGadget easy with the actual addresses in the process.

Just use the `rop` command!

![](assets/caps/rop_grep.png)

## Search

Pwndbg makes searching the target memory space easy, with a complete and easy-to-use interface.  Whether you're searching for bytes, strings, or various sizes of integer values or pointers, it's a simple command away.

![](assets/caps/search.png)

## Finding Leaks
![](assets/caps/leakfind.png)
Finding leak chains can be done using the `leakfind` command. It recursively inspects address ranges for pointers, and reports on all pointers found.


## Telescope

Inspecting memory dumps is easy with the `telescope` command.  It recursively dereferences a range of memory, letting you see everything at once.  As an added bonus, Pwndbg checks all of the available registers to see if they point into the memory range.

## Virtual Memory Maps

Pwndbg enhances the standard memory map listing, and allows easy searching.

![](assets/caps/vmmap.png)
![](assets/caps/vmmap2.png)
![](assets/caps/vmmap_pc.png)
![](assets/caps/vmmap_register.png)
![](assets/caps/vmmap_stack.png)

## Windbg Compatibility

Pwndbg has a complete windbg compatibility layer.  You can `dd`, `dps`, `eq`, and even `eb eip 90` to your heart's content.

![](assets/caps/windbg.png)
